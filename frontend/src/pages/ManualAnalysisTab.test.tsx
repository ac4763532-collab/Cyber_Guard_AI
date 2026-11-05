/**
 * Tests for LogAnalysisPage's Manual Analysis tab: paste-mode analyze
 * call shape + results rendering, upload-mode preview->analyze flow
 * (driven through the real LogFileDropzone, not mocked), the "Ad-hoc ·
 * not saved" framing, and the Paste/Upload toggle.
 *
 * ManualAnalysisTab isn't separately exported, so these drive it through
 * LogAnalysisPage with its default tab (manual).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ToastProvider } from '@/components/ui'
import { LogAnalysisPage } from './LogAnalysisPage'
import { analysisApi } from '@/services/api'

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

function renderManualTab() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <MemoryRouter initialEntries={['/analysis/logs']}>
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <LogAnalysisPage />
        </ToastProvider>
      </QueryClientProvider>
    </MemoryRouter>
  )
}

function makeLogFile(name = 'auth.log', content = 'line one\nline two\n') {
  return new File([content], name, { type: 'text/plain' })
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('ManualAnalysisTab - ad-hoc framing', () => {
  it('shows the non-persistence explanation and the renamed sample-logs button', () => {
    renderManualTab()
    expect(
      screen.getByText(/Ad-hoc analysis only.*results here are never saved as Log Events/i)
    ).toBeInTheDocument()
    expect(screen.getByText('Load Sample Logs')).toBeInTheDocument()
    expect(screen.queryByText(/\[DEV\]/)).not.toBeInTheDocument()
  })
})

describe('ManualAnalysisTab - paste mode', () => {
  it('submits log_content/log_type/source and renders results', async () => {
    ;(analysisApi.analyzeLogs as any).mockResolvedValue({
      risk_score: 80,
      severity: 'high',
      findings: [{ name: 'Brute force', description: 'Many failed logins', severity: 'high' }],
      recommendations: ['Block the source IP'],
    })
    renderManualTab()

    await userEvent.type(
      screen.getByPlaceholderText('Paste log entries here...'),
      'ERROR auth failed'
    )
    await userEvent.click(screen.getByRole('button', { name: /Analyze Logs/i }))

    await waitFor(() => {
      expect(analysisApi.analyzeLogs).toHaveBeenCalledWith({
        log_content: 'ERROR auth failed',
        log_type: 'system',
        source: 'system',
      })
    })

    expect(await screen.findByText('Brute force')).toBeInTheDocument()
    expect(screen.getByText('Block the source IP')).toBeInTheDocument()
    expect(screen.getByText('80')).toBeInTheDocument()
  })

  it('loading sample logs fills the textarea and sets source to security', async () => {
    renderManualTab()
    await userEvent.click(screen.getByText('Load Sample Logs'))

    const textarea = screen.getByPlaceholderText('Paste log entries here...') as HTMLTextAreaElement
    expect(textarea.value).toContain('Authentication failed for user admin')

    const select = screen.getByDisplayValue('Security Logs')
    expect(select).toBeInTheDocument()
  })
})

describe('ManualAnalysisTab - upload mode', () => {
  it('previews a dropped file, then analyzes it on click', async () => {
    ;(analysisApi.uploadLogFile as any)
      .mockResolvedValueOnce({
        detected_source_type: 'linux_ssh',
        parsed_event_count: 2,
        skipped_line_count: 0,
        preview_events: [{ message: 'line one' }],
      })
      .mockResolvedValueOnce({
        risk_score: 10,
        severity: 'low',
        findings: [],
        recommendations: [],
      })
    renderManualTab()

    await userEvent.click(screen.getByRole('button', { name: 'Upload' }))

    const file = makeLogFile()
    const input = document.querySelector('input[type="file"]') as HTMLInputElement
    await userEvent.upload(input, file)

    expect(await screen.findByText('linux_ssh')).toBeInTheDocument()
    expect(screen.getByText(/2 parsed/)).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: /Analyze Log File/i }))

    await waitFor(() => {
      expect(analysisApi.uploadLogFile).toHaveBeenCalledTimes(2)
    })
    expect(await screen.findByText('10')).toBeInTheDocument()
  })

  it('disables Analyze Log File until a file is selected', async () => {
    renderManualTab()
    await userEvent.click(screen.getByRole('button', { name: 'Upload' }))

    expect(screen.getByRole('button', { name: /Analyze Log File/i })).toBeDisabled()
  })

  it('surfaces a preview error without blocking a retry', async () => {
    ;(analysisApi.uploadLogFile as any).mockRejectedValueOnce({
      response: { status: 400, data: { detail: 'Could not parse file' } },
    })
    renderManualTab()
    await userEvent.click(screen.getByRole('button', { name: 'Upload' }))

    const input = document.querySelector('input[type="file"]') as HTMLInputElement
    await userEvent.upload(input, makeLogFile())

    expect(await screen.findByText('Could not parse file')).toBeInTheDocument()
  })
})

describe('ManualAnalysisTab - Paste/Upload toggle', () => {
  it('switching modes clears any previous result', async () => {
    ;(analysisApi.analyzeLogs as any).mockResolvedValue({
      risk_score: 50,
      severity: 'medium',
      findings: [],
      recommendations: [],
    })
    renderManualTab()

    await userEvent.type(screen.getByPlaceholderText('Paste log entries here...'), 'test')
    await userEvent.click(screen.getByRole('button', { name: /Analyze Logs/i }))
    expect(await screen.findByText('50')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Upload' }))
    expect(screen.getByText('Submit logs to see analysis results')).toBeInTheDocument()
  })
})
