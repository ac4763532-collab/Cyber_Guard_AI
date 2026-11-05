/**
 * Tests for the STEP 9 Android migration in LogAnalysisPage.tsx.
 *
 * Covers:
 *  - source-type selection (Android Device replaces Web Application)
 *  - Android configuration form behavior (required device_serial, conditional
 *    adb_port, submitted payload shape)
 *  - API integration (logsApi.createSource / restartSource called correctly)
 *  - regression: Windows / Linux source types still render and submit their
 *    existing payload shapes unchanged
 *  - SourceCard rendering for an android_adb source (icon/label/device
 *    serial/connection method, no stale web_application ingestion panel)
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithProviders } from '@/test/test-utils'
import { AddSourceModal, SourceCard } from './LogAnalysisPage'
import { logsApi } from '@/services/api'
import type { LogSourceResponse } from '@/types'

// Fills in the full LogSourceResponse shape with honest defaults
// (collector_status: null = "no live supervisor", matching what the real
// backend sends for a source with no active CollectorManager entry) so
// each test only needs to specify the fields it actually cares about.
function makeSource(overrides: Partial<LogSourceResponse>): LogSourceResponse {
  return {
    id: 'src-test',
    name: 'Test Source',
    description: null,
    source_type: 'windows_event',
    collector_type: 'windows_agent',
    status: 'active',
    last_event_at: null,
    event_count: 0,
    error_message: null,
    configuration: {},
    created_by: 'user-1',
    organization_id: 'org-1',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    collector_status: null,
    ...overrides,
  }
}

vi.mock('@/services/api', () => ({
  logsApi: {
    createSource: vi.fn(),
    restartSource: vi.fn(),
  },
  analysisApi: {},
}))

describe('AddSourceModal - source type selection', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('offers Android Device instead of Web Application', () => {
    renderWithProviders(<AddSourceModal onClose={vi.fn()} />)

    expect(screen.getByText('Android Device')).toBeInTheDocument()
    expect(screen.queryByText('Web Application')).not.toBeInTheDocument()
    expect(screen.queryByText(/web application/i)).not.toBeInTheDocument()
  })

  it('still offers Windows Event Log and Linux / SSH (regression)', () => {
    renderWithProviders(<AddSourceModal onClose={vi.fn()} />)

    expect(screen.getByText('Windows Event Log')).toBeInTheDocument()
    expect(screen.getByText('Linux / SSH')).toBeInTheDocument()
  })
})

describe('AddSourceModal - Android configuration form', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  async function goToAndroidConfig() {
    renderWithProviders(<AddSourceModal onClose={vi.fn()} />)
    await userEvent.click(screen.getByText('Android Device'))
  }

  it('shows the Device Serial field as required and no ADB port field by default', async () => {
    await goToAndroidConfig()

    const serialInput = screen.getByPlaceholderText(/emulator-5554/i)
    expect(serialInput).toBeRequired()
    expect(screen.queryByLabelText(/ADB Port/i)).not.toBeInTheDocument()
  })

  it('reveals the ADB Port field only once a Network ADB Host is entered', async () => {
    await goToAndroidConfig()

    // Network ADB Host / Port now live under the collapsed "Advanced /
    // network device settings" disclosure.
    await userEvent.click(screen.getByText('Advanced / network device settings'))

    expect(screen.queryByText('ADB Port')).not.toBeInTheDocument()

    await userEvent.type(
      screen.getByPlaceholderText(/connected via USB/i),
      '192.168.1.20'
    )

    expect(screen.getByText('ADB Port')).toBeInTheDocument()
  })

  it('blocks submission when device_serial is empty (HTML required validation)', async () => {
    await goToAndroidConfig()
    await userEvent.type(screen.getByPlaceholderText(/DC01 Windows Events/i), 'My Android Device')

    const serialInput = screen.getByPlaceholderText(/emulator-5554/i) as HTMLInputElement
    expect(serialInput.value).toBe('')
    expect(serialInput.validity.valid).toBe(false)

    await userEvent.click(screen.getByText('Add Source'))

    expect(logsApi.createSource).not.toHaveBeenCalled()
  })

  it('submits a USB device with no adb_host/adb_port in the payload', async () => {
    ;(logsApi.createSource as any).mockResolvedValue({ data: {} })
    await goToAndroidConfig()

    await userEvent.type(screen.getByPlaceholderText(/DC01 Windows Events/i), 'Pixel Lab Device')
    await userEvent.type(screen.getByPlaceholderText(/emulator-5554/i), 'ZY223JL4GF')
    await userEvent.click(screen.getByText('Add Source'))

    await waitFor(() => {
      expect(logsApi.createSource).toHaveBeenCalledWith({
        name: 'Pixel Lab Device',
        source_type: 'android_adb',
        configuration: {
          device_serial: 'ZY223JL4GF',
        },
      })
    })
  })

  it('submits a network ADB device with adb_host and parsed adb_port', async () => {
    ;(logsApi.createSource as any).mockResolvedValue({ data: {} })
    await goToAndroidConfig()

    await userEvent.type(screen.getByPlaceholderText(/DC01 Windows Events/i), 'Networked Device')
    await userEvent.type(screen.getByPlaceholderText(/emulator-5554/i), 'emulator-5554')
    // Network ADB Host / Port now live under the collapsed "Advanced /
    // network device settings" disclosure.
    await userEvent.click(screen.getByText('Advanced / network device settings'))
    await userEvent.type(screen.getByPlaceholderText(/connected via USB/i), '192.168.1.20')

    const portInput = screen.getByDisplayValue('5555')
    await userEvent.clear(portInput)
    await userEvent.type(portInput, '5557')

    await userEvent.click(screen.getByText('Add Source'))

    await waitFor(() => {
      expect(logsApi.createSource).toHaveBeenCalledWith({
        name: 'Networked Device',
        source_type: 'android_adb',
        configuration: {
          device_serial: 'emulator-5554',
          adb_host: '192.168.1.20',
          adb_port: 5557,
        },
      })
    })
  })

  it('trims whitespace from device_serial and adb_host before submitting', async () => {
    ;(logsApi.createSource as any).mockResolvedValue({ data: {} })
    await goToAndroidConfig()

    await userEvent.type(screen.getByPlaceholderText(/DC01 Windows Events/i), 'Trim Test')
    await userEvent.type(screen.getByPlaceholderText(/emulator-5554/i), '  ZY223JL4GF  ')
    await userEvent.click(screen.getByText('Add Source'))

    await waitFor(() => {
      expect(logsApi.createSource).toHaveBeenCalledWith(
        expect.objectContaining({
          configuration: { device_serial: 'ZY223JL4GF' },
        })
      )
    })
  })

  it('states the backend-host/pre-authorized-device constraint plainly (not general remote support)', async () => {
    await goToAndroidConfig()

    expect(
      screen.getByText(/does not support collecting from an arbitrary remote end user's personal phone/i)
    ).toBeInTheDocument()
  })
})

describe('AddSourceModal - Windows/Linux regression', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('submits the existing Windows payload shape unchanged', async () => {
    ;(logsApi.createSource as any).mockResolvedValue({ data: {} })
    renderWithProviders(<AddSourceModal onClose={vi.fn()} />)

    await userEvent.click(screen.getByText('Windows Event Log'))
    await userEvent.type(screen.getByPlaceholderText(/DC01 Windows Events/i), 'DC01')
    await userEvent.click(screen.getByText('Add Source'))

    await waitFor(() => {
      expect(logsApi.createSource).toHaveBeenCalledWith({
        name: 'DC01',
        source_type: 'windows_event',
        configuration: {},
      })
    })
  })

  it('submits the Linux/SSH payload with username/host_key/credentials and checkbox log paths', async () => {
    ;(logsApi.createSource as any).mockResolvedValue({ data: {} })
    renderWithProviders(<AddSourceModal onClose={vi.fn()} />)

    await userEvent.click(screen.getByText('Linux / SSH'))
    await userEvent.type(screen.getByPlaceholderText(/DC01 Windows Events/i), 'Web01')
    await userEvent.type(screen.getByPlaceholderText(/192.168.1.50/i), 'web01.corp.local')
    await userEvent.type(screen.getByPlaceholderText(/e.g. ubuntu or root/i), 'ubuntu')
    await userEvent.type(
      screen.getByPlaceholderText(/BEGIN OPENSSH PRIVATE KEY/i),
      '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----'
    )
    await userEvent.type(screen.getByPlaceholderText(/ssh-ed25519 AAAA/i), 'ssh-ed25519 AAAAtest')
    // Default-checked log paths (auth.log + secure) are left as-is.
    await userEvent.click(screen.getByText('Add Source'))

    await waitFor(() => {
      expect(logsApi.createSource).toHaveBeenCalledWith({
        name: 'Web01',
        source_type: 'linux_ssh',
        configuration: {
          hostname: 'web01.corp.local',
          port: 22,
          log_paths: ['/var/log/auth.log', '/var/log/secure'],
        },
        credentials: {
          username: 'ubuntu',
          host_key: 'ssh-ed25519 AAAAtest',
          auth_method: 'private_key',
          private_key: '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----',
        },
      })
    })
  })
})

describe('SourceCard - android_adb source', () => {
  const androidSource = makeSource({
    id: 'src-android-1',
    name: 'Pixel Lab Device',
    source_type: 'android_adb',
    status: 'active',
    event_count: 42,
    last_event_at: new Date().toISOString(),
    configuration: {
      device_serial: 'ZY223JL4GF',
    },
  })

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the Android label and device serial in the Device tile', () => {
    renderWithProviders(<SourceCard source={androidSource} onDelete={vi.fn()} />)

    expect(screen.getByText('Android Device')).toBeInTheDocument()
    expect(screen.getByText('Device')).toBeInTheDocument()
    expect(screen.getByText('ZY223JL4GF')).toBeInTheDocument()
  })

  it('shows USB as the connection method when no adb_host is configured, once expanded', async () => {
    renderWithProviders(<SourceCard source={androidSource} onDelete={vi.fn()} />)

    await userEvent.click(screen.getByLabelText('Expand source details'))

    expect(screen.getByText('Connection Method')).toBeInTheDocument()
    expect(screen.getByText('USB')).toBeInTheDocument()
  })

  it('shows the network ADB host:port as the connection method when configured', async () => {
    const networkedSource = makeSource({
      ...androidSource,
      configuration: { device_serial: 'emulator-5554', adb_host: '192.168.1.20', adb_port: 5557 },
    })
    renderWithProviders(<SourceCard source={networkedSource} onDelete={vi.fn()} />)

    await userEvent.click(screen.getByLabelText('Expand source details'))

    expect(screen.getByText('Network ADB (192.168.1.20:5557)')).toBeInTheDocument()
  })

  it('does not render a stale web_application ingestion-endpoint block', () => {
    renderWithProviders(<SourceCard source={androidSource} onDelete={vi.fn()} />)

    expect(screen.queryByText(/ingestion endpoint/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/\/logs\/web\/ingest/i)).not.toBeInTheDocument()
  })

  it('calls restartSource when retrying a failed android_adb collector', async () => {
    ;(logsApi.restartSource as any).mockResolvedValue({ data: {} })
    const erroredSource = makeSource({
      ...androidSource,
      status: 'error',
      error_message: 'Device unauthorized - accept the USB debugging prompt on the device.',
    })
    renderWithProviders(<SourceCard source={erroredSource} onDelete={vi.fn()} />)

    await userEvent.click(screen.getByText('Retry collector'))

    await waitFor(() => {
      expect(logsApi.restartSource).toHaveBeenCalledWith('src-android-1')
    })
  })
})

describe('SourceCard - Windows/Linux regression', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('still renders the Host tile label (not "Device") for a windows_event source', () => {
    const windowsSource = makeSource({
      id: 'src-win-1',
      name: 'Primary Domain Controller',
      source_type: 'windows_event',
      status: 'active',
      event_count: 10,
      last_event_at: new Date().toISOString(),
      configuration: { computer_name: 'DC01' },
    })
    renderWithProviders(<SourceCard source={windowsSource} onDelete={vi.fn()} />)

    expect(screen.getByText('Windows Event Log')).toBeInTheDocument()
    expect(screen.getByText('Host')).toBeInTheDocument()
    expect(screen.getByText('DC01')).toBeInTheDocument()
  })

  it('still renders Linux / SSH label and hostname for a linux_ssh source', () => {
    const linuxSource = makeSource({
      id: 'src-linux-1',
      name: 'Web01',
      source_type: 'linux_ssh',
      status: 'active',
      event_count: 5,
      last_event_at: new Date().toISOString(),
      configuration: { hostname: 'web01.corp.local', port: 22, log_path: '/var/log/auth.log' },
    })
    renderWithProviders(<SourceCard source={linuxSource} onDelete={vi.fn()} />)

    expect(screen.getByText('Linux / SSH')).toBeInTheDocument()
    expect(screen.getByText('web01.corp.local')).toBeInTheDocument()
  })
})
