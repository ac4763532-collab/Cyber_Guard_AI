/**
 * CyberGuard AI - Log Analysis Page
 *
 * Primary: Log Sources dashboard (Windows, Linux/SSH, Android/ADB)
 * Secondary: Log Events list
 * Tertiary: Manual/troubleshooting log analysis
 */

import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  FileText,
  Send,
  AlertTriangle,
  CheckCircle2,
  Shield,
  RefreshCw,
  XCircle,
  Plus,
  Trash2,
  Monitor,
  Terminal,
  Smartphone,
  Activity,
  ChevronDown,
  ChevronRight,
  Copy,
  Eye,
  EyeOff,
  Search,
  Upload,
  Clipboard,
  FlaskConical,
  Hash,
  Clock,
  Server,
  Users,
  Download,
  Info,
  Lightbulb,
  ThumbsUp,
  ThumbsDown,
  Gauge,
  ShieldCheck,
  Radar,
} from 'lucide-react'
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { clsx } from 'clsx'
import { logsApi, analysisApi, feedbackApi } from '@/services/api'
import { LogFileDropzone } from '@/components/LogFileDropzone'
import { CollapsibleSection } from '@/components/EmailInvestigationReport/shared/badges'
import { SeverityBadge, StatusDot, SEVERITY_COLORS, useToast, RiskGauge, StatTile, riskLabel, exportReport, DetectionReportButton } from '@/components/ui'
import type { LogSourceResponse } from '@/types'

// ============================================================================
// Shared helpers
// ============================================================================
//
// SeverityBadge, StatusDot, and SEVERITY_COLORS now live in
// frontend/src/components/ui/Badge.tsx (imported above) so this page's
// badges and SourceHealthOverview's chart colors can never drift apart -
// previously each kept its own separate color map.

function formatRelativeTime(ts: string | null | undefined): string {
  if (!ts) return '—'
  const diff = Date.now() - new Date(ts).getTime()
  const sec = Math.floor(diff / 1000)
  if (sec < 60) return `${sec}s ago`
  const min = Math.floor(sec / 60)
  if (min < 60) return `${min}m ago`
  const hr = Math.floor(min / 60)
  if (hr < 24) return `${hr}h ago`
  return `${Math.floor(hr / 24)}d ago`
}

// ============================================================================
// Add Source Modal
// ============================================================================

// Backend only supports these 3 types today (see LogSourceType in
// backend/app/logs/models.py - "Do NOT add unsupported types without
// implementing collectors"). Keep this list in sync with that enum.
// STEP 9: web_application was removed and replaced with android_adb.
export type SourceType = 'windows_event' | 'linux_ssh' | 'android_adb'

// Linux SSH credential/host-key requirements mirrored from
// LinuxSSHCollectorConfig (backend/app/logs/collectors/linux.py:163-204) so
// the form can validate before submitting - the backend remains the real
// authority (e.g. StrictHostKeyPolicy does an exact byte-for-byte host key
// comparison at actual connect time; this is a UX pre-check only).
type LinuxAuthMethod = 'private_key' | 'password'

// Mirrors ALL_SUPPORTED_PATHS / DEFAULT_LOG_PATHS in collectors/linux.py.
// Any path outside this set fails backend validation, so the form offers
// exactly these 4 as checkboxes rather than free text.
const LINUX_LOG_PATH_OPTIONS = [
  { path: '/var/log/auth.log', label: '/var/log/auth.log', hint: 'Debian / Ubuntu auth log' },
  { path: '/var/log/secure', label: '/var/log/secure', hint: 'RHEL / CentOS auth log' },
  { path: '/var/log/syslog', label: '/var/log/syslog', hint: 'Debian / Ubuntu system log' },
  { path: '/var/log/messages', label: '/var/log/messages', hint: 'RHEL / CentOS system log' },
]
const LINUX_DEFAULT_LOG_PATHS = ['/var/log/auth.log', '/var/log/secure']

interface AddSourceFormData {
  name: string
  windows: { computerName: string }
  linux: {
    hostname: string
    port: string
    username: string
    authMethod: LinuxAuthMethod
    privateKey: string
    privateKeyPassphrase: string
    password: string
    hostKey: string
    logPaths: string[]
  }
  android: { deviceSerial: string; adbHost: string; adbPort: string }
}

const INITIAL_FORM_DATA: AddSourceFormData = {
  name: '',
  windows: { computerName: '' },
  linux: {
    hostname: '',
    port: '22',
    username: '',
    authMethod: 'private_key',
    privateKey: '',
    privateKeyPassphrase: '',
    password: '',
    hostKey: '',
    logPaths: [...LINUX_DEFAULT_LOG_PATHS],
  },
  android: { deviceSerial: '', adbHost: '', adbPort: '5555' },
}

// Lenient hostname/IPv4 format check - a pre-submit UX helper only, not a
// substitute for the backend's own validation.
function isValidHostnameFormat(v: string): boolean {
  const trimmed = v.trim()
  if (!trimmed) return false
  return /^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$/.test(trimmed)
}

function isValidPortFormat(v: string): boolean {
  const n = parseInt(v, 10)
  return Number.isInteger(n) && n >= 1 && n <= 65535
}

// Mirrors the shape checked by validate_host_key in collectors/linux.py:
// "key-type key-data", e.g. "ssh-ed25519 AAAA...".
function isValidHostKeyFormat(v: string): boolean {
  const trimmed = v.trim()
  if (!trimmed) return false
  const parts = trimmed.split(/\s+/)
  return parts.length >= 2 && /^(ssh-|ecdsa-|sk-)/.test(parts[0])
}

export function AddSourceModal({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient()
  const [step, setStep] = useState<'type' | 'config'>('type')
  const [sourceType, setSourceType] = useState<SourceType>('windows_event')
  const [ingestionKey, setIngestionKey] = useState<string | null>(null)
  const [showKey, setShowKey] = useState(false)
  const [copied, setCopied] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [formData, setFormData] = useState<AddSourceFormData>(INITIAL_FORM_DATA)

  // Accessibility: Escape closes the modal, same as clicking the X or the
  // backdrop. Only attached while the modal is actually mounted.
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  const createMutation = useMutation({
    mutationFn: (payload: any) => logsApi.createSource(payload),
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ['log-sources'] })
      // If backend returns an ingestion key, show it once
      if (data.ingestion_key) {
        setIngestionKey(data.ingestion_key)
      } else {
        onClose()
      }
    },
  })

  const handleCopyKey = () => {
    if (ingestionKey) {
      navigator.clipboard.writeText(ingestionKey)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  const toggleLogPath = (path: string) => {
    setFormData((prev) => ({
      ...prev,
      linux: {
        ...prev.linux,
        logPaths: prev.linux.logPaths.includes(path)
          ? prev.linux.logPaths.filter((p) => p !== path)
          : [...prev.linux.logPaths, path],
      },
    }))
  }

  // Whether the form has enough genuinely-required information to submit.
  // Mirrors the backend's actual required fields per source type (see
  // LinuxSSHCollectorConfig / AndroidADBCollectorConfig / WindowsCollectorConfig)
  // rather than only the native HTML `required` attributes, since the
  // Linux form collects fields across both the main form and the
  // collapsed "Advanced settings" section.
  const canSubmit = useMemo(() => {
    if (!formData.name.trim()) return false
    if (sourceType === 'windows_event') return true
    if (sourceType === 'android_adb') return !!formData.android.deviceSerial.trim()
    if (sourceType === 'linux_ssh') {
      const l = formData.linux
      const hasAuth =
        l.authMethod === 'password' ? l.password.length > 0 : l.privateKey.trim().length > 0
      return (
        isValidHostnameFormat(l.hostname) &&
        !!l.username.trim() &&
        isValidHostKeyFormat(l.hostKey) &&
        hasAuth &&
        l.logPaths.length > 0
      )
    }
    return false
  }, [formData, sourceType])

  // Shared between actually creating the source and the "Test connection"
  // preflight check below - both need the exact same source_type/
  // configuration/credentials shape, built from the same form fields.
  const buildSourcePayload = (): {
    source_type: SourceType
    configuration: Record<string, unknown>
    credentials?: Record<string, unknown>
  } => {
    const payload: {
      source_type: SourceType
      configuration: Record<string, unknown>
      credentials?: Record<string, unknown>
    } = {
      source_type: sourceType,
      configuration: {},
    }
    if (sourceType === 'windows_event') {
      // WindowsCollectorConfig (backend/app/logs/collectors/windows.py)
      // reads computer_name, not hostname. Only send computer_name when
      // non-empty; omitting it entirely lets the backend's default (the
      // CyberGuard server's own local machine) apply.
      payload.configuration = formData.windows.computerName
        ? { computer_name: formData.windows.computerName }
        : {}
    } else if (sourceType === 'linux_ssh') {
      const l = formData.linux
      payload.configuration = {
        hostname: l.hostname.trim(),
        port: parseInt(l.port, 10) || 22,
        log_paths: l.logPaths,
      }
      // Credentials go through the write-only, server-side-encrypted
      // `credentials` field (never echoed back) rather than plaintext
      // `configuration` - see LogSourceCreate.credentials in
      // backend/app/logs/models.py.
      payload.credentials = {
        username: l.username.trim(),
        host_key: l.hostKey.trim(),
        auth_method: l.authMethod,
        ...(l.authMethod === 'password'
          ? { password: l.password }
          : {
              private_key: l.privateKey,
              ...(l.privateKeyPassphrase ? { private_key_passphrase: l.privateKeyPassphrase } : {}),
            }),
      }
    } else if (sourceType === 'android_adb') {
      // AndroidADBCollectorConfig (backend/app/logs/collectors/android.py):
      // device_serial is required; adb_host/adb_port only make sense
      // together and are omitted entirely for a USB-attached device.
      payload.configuration = {
        device_serial: formData.android.deviceSerial.trim(),
        ...(formData.android.adbHost.trim()
          ? {
              adb_host: formData.android.adbHost.trim(),
              adb_port: parseInt(formData.android.adbPort, 10) || 5555,
            }
          : {}),
      }
    }
    return payload
  }

  const checkMutation = useMutation({
    mutationFn: () => logsApi.checkConnectionPreview(buildSourcePayload()),
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!canSubmit || createMutation.isPending) return
    createMutation.mutate({ name: formData.name, ...buildSourcePayload() })
  }

  // After creation with an ingestion key
  if (ingestionKey) {
    return (
      <div
        className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4"
        onClick={onClose}
      >
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="add-source-created-title"
          onClick={(e) => e.stopPropagation()}
          className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-lg"
        >
          <div className="px-6 py-4 border-b border-slate-700 flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
            <h2 id="add-source-created-title" className="text-lg font-semibold text-white">Source Created</h2>
          </div>
          <div className="p-6 space-y-4">
            <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
              <p className="text-yellow-400 font-medium text-sm">Save this ingestion key now</p>
              <p className="text-yellow-400/70 text-xs mt-1">
                It will not be shown again. Use it to authenticate log submissions to this source.
              </p>
            </div>
            <div className="relative">
              <div className="bg-slate-800 border border-slate-700 rounded-lg px-4 py-3 font-mono text-sm text-white pr-20 break-all">
                {showKey ? ingestionKey : '••••••••••••••••••••••••••••••••'}
              </div>
              <div className="absolute right-2 top-1/2 -translate-y-1/2 flex gap-1">
                <button
                  onClick={() => setShowKey(!showKey)}
                  className="p-1.5 text-slate-400 hover:text-white"
                >
                  {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
                <button
                  onClick={handleCopyKey}
                  className="p-1.5 text-slate-400 hover:text-white"
                >
                  <Copy className="w-4 h-4" />
                </button>
              </div>
            </div>
            {copied && <p className="text-emerald-400 text-xs">Copied to clipboard</p>}
          </div>
          <div className="px-6 py-4 border-t border-slate-700 flex justify-end">
            <button
              onClick={onClose}
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors"
            >
              Done
            </button>
          </div>
        </div>
      </div>
    )
  }

  const sourceTypes = [
    { id: 'windows_event', label: 'Windows Event Log', icon: Monitor, desc: 'Collect Windows security, system, and application events' },
    { id: 'linux_ssh', label: 'Linux / SSH', icon: Terminal, desc: 'Collect Linux syslog or auth log entries via SSH' },
    { id: 'android_adb', label: 'Android Device', icon: Smartphone, desc: 'Collect Android device logs via ADB/logcat' },
  ]

  const inputClass =
    'w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500'
  const fieldErrorClass = 'mt-1 text-xs text-red-400'

  return (
    <div
      className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4"
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="add-source-title"
        onClick={(e) => e.stopPropagation()}
        className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-lg max-h-[90vh] overflow-y-auto"
      >
        <div className="px-6 py-4 border-b border-slate-700 flex items-center justify-between sticky top-0 bg-slate-900">
          <h2 id="add-source-title" className="text-lg font-semibold text-white">Add Log Source</h2>
          <button onClick={onClose} aria-label="Close" className="text-slate-400 hover:text-white">
            <XCircle className="w-5 h-5" />
          </button>
        </div>

        {step === 'type' ? (
          <div className="p-6 space-y-3">
            <p className="text-sm text-slate-400 mb-4">Choose the type of log source to connect.</p>
            {sourceTypes.map(({ id, label, icon: Icon, desc }) => (
              <button
                key={id}
                onClick={() => { setSourceType(id as SourceType); setStep('config') }}
                className="w-full flex items-start gap-4 p-4 bg-slate-800/50 hover:bg-slate-800 border border-slate-700 rounded-lg transition-colors text-left"
              >
                <div className="p-2 bg-slate-700 rounded-lg mt-0.5">
                  <Icon className="w-5 h-5 text-cyan-400" />
                </div>
                <div>
                  <p className="text-white font-medium">{label}</p>
                  <p className="text-sm text-slate-400">{desc}</p>
                </div>
                <ChevronRight className="w-4 h-4 text-slate-500 ml-auto mt-1 flex-shrink-0" />
              </button>
            ))}
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="p-6 space-y-4">
            <div>
              <label className="block text-sm text-slate-400 mb-1">Source Name *</label>
              <input
                type="text"
                required
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                className={inputClass}
                placeholder="e.g., DC01 Windows Events"
              />
            </div>

            {sourceType === 'windows_event' && (
              <div className="space-y-3">
                <p className="text-sm text-slate-400">
                  This collects Windows security events from the computer running the
                  CyberGuard AI server itself - not from your own computer or browser.
                </p>
                <div>
                  <label className="block text-sm text-slate-400 mb-1">
                    Another computer's name <span className="text-slate-500">(optional)</span>
                  </label>
                  <input
                    type="text"
                    value={formData.windows.computerName}
                    onChange={(e) =>
                      setFormData({ ...formData, windows: { computerName: e.target.value } })
                    }
                    className={inputClass}
                    placeholder="Leave blank to use this server"
                  />
                  <p className="text-xs text-slate-500 mt-1">
                    Leave this blank for "This computer" (the CyberGuard server). Only fill
                    it in if the server has permission to read event logs from a different,
                    named Windows computer on the same network - this is uncommon and
                    requires domain-level permissions.
                  </p>
                </div>
                <p className="text-xs text-slate-500">
                  Reads the Security event log. Collected event IDs: 4624, 4625, 4634,
                  4648, 4672, 4688, 4720, 4726 (sign-ins, failed logons, privilege use,
                  new processes, and account changes).
                </p>
              </div>
            )}

            {sourceType === 'linux_ssh' && (
              <>
                <div>
                  <label className="block text-sm text-slate-400 mb-1">Hostname or IP address *</label>
                  <input
                    type="text"
                    required
                    value={formData.linux.hostname}
                    onChange={(e) =>
                      setFormData({ ...formData, linux: { ...formData.linux, hostname: e.target.value } })
                    }
                    className={inputClass}
                    placeholder="192.168.1.50 or server.corp.local"
                  />
                  {formData.linux.hostname && !isValidHostnameFormat(formData.linux.hostname) && (
                    <p className={fieldErrorClass}>
                      Enter a valid hostname or IP address, e.g. 192.168.1.50 or server.corp.local.
                    </p>
                  )}
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-1">Username *</label>
                  <input
                    type="text"
                    required
                    value={formData.linux.username}
                    onChange={(e) =>
                      setFormData({ ...formData, linux: { ...formData.linux, username: e.target.value } })
                    }
                    className={inputClass}
                    placeholder="e.g. ubuntu or root"
                  />
                  <p className="text-xs text-slate-500 mt-1">
                    The SSH user CyberGuard should log in as on that machine.
                  </p>
                </div>

                <div>
                  <label className="block text-sm text-slate-400 mb-2">How should CyberGuard sign in?</label>
                  <div className="flex gap-2">
                    {(['private_key', 'password'] as LinuxAuthMethod[]).map((method) => (
                      <button
                        key={method}
                        type="button"
                        onClick={() =>
                          setFormData({ ...formData, linux: { ...formData.linux, authMethod: method } })
                        }
                        className={clsx(
                          'flex-1 px-3 py-2 rounded-lg border text-sm transition-colors',
                          formData.linux.authMethod === method
                            ? 'bg-cyan-600 border-cyan-500 text-white'
                            : 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
                        )}
                      >
                        {method === 'private_key' ? 'Private key' : 'Password'}
                      </button>
                    ))}
                  </div>
                  <p className="text-xs text-slate-500 mt-1">
                    {formData.linux.authMethod === 'private_key'
                      ? 'Paste the private key for an account already authorized on that machine (recommended).'
                      : 'Use the account password. This is encrypted before it is stored and is never shown again.'}
                  </p>
                </div>

                {formData.linux.authMethod === 'private_key' ? (
                  <div>
                    <label className="block text-sm text-slate-400 mb-1">Private Key *</label>
                    <textarea
                      required
                      value={formData.linux.privateKey}
                      onChange={(e) =>
                        setFormData({ ...formData, linux: { ...formData.linux, privateKey: e.target.value } })
                      }
                      rows={4}
                      className={clsx(inputClass, 'font-mono text-xs resize-y')}
                      placeholder={'-----BEGIN OPENSSH PRIVATE KEY-----\n...'}
                    />
                    <p className="text-xs text-slate-500 mt-1">
                      Encrypted before it is stored. It is never shown again after you submit this form.
                    </p>
                  </div>
                ) : (
                  <div>
                    <label className="block text-sm text-slate-400 mb-1">Password *</label>
                    <div className="relative">
                      <input
                        type={showPassword ? 'text' : 'password'}
                        required
                        value={formData.linux.password}
                        onChange={(e) =>
                          setFormData({ ...formData, linux: { ...formData.linux, password: e.target.value } })
                        }
                        className={clsx(inputClass, 'pr-10')}
                        placeholder="SSH account password"
                        autoComplete="new-password"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        aria-label={showPassword ? 'Hide password' : 'Show password'}
                        className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-slate-400 hover:text-white"
                      >
                        {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                    <p className="text-xs text-slate-500 mt-1">
                      Encrypted before it is stored. It is never shown again after you submit this form.
                    </p>
                  </div>
                )}

                <div>
                  <label className="block text-sm text-slate-400 mb-1">Host Key *</label>
                  <input
                    type="text"
                    required
                    value={formData.linux.hostKey}
                    onChange={(e) =>
                      setFormData({ ...formData, linux: { ...formData.linux, hostKey: e.target.value } })
                    }
                    className={clsx(inputClass, 'font-mono text-xs')}
                    placeholder="ssh-ed25519 AAAA..."
                  />
                  {formData.linux.hostKey && !isValidHostKeyFormat(formData.linux.hostKey) && (
                    <p className={fieldErrorClass}>
                      This should look like "ssh-ed25519 AAAA..." - a key type followed by the key data.
                    </p>
                  )}
                  <p className="text-xs text-slate-500 mt-1">
                    Confirms you're connecting to the right machine, not an impersonator. From a
                    terminal that can already reach that computer, run{' '}
                    <code className="text-slate-400">
                      ssh-keyscan -t ed25519 {formData.linux.hostname.trim() || '&lt;hostname&gt;'}
                    </code>{' '}
                    and paste the result here.
                  </p>
                </div>

                <CollapsibleSection title="Advanced settings" icon={Terminal}>
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm text-slate-400 mb-1">SSH Port</label>
                      <input
                        type="number"
                        value={formData.linux.port}
                        onChange={(e) =>
                          setFormData({ ...formData, linux: { ...formData.linux, port: e.target.value } })
                        }
                        className={inputClass}
                        placeholder="22"
                      />
                      {formData.linux.port && !isValidPortFormat(formData.linux.port) && (
                        <p className={fieldErrorClass}>Enter a port number between 1 and 65535.</p>
                      )}
                    </div>
                    {formData.linux.authMethod === 'private_key' && (
                      <div>
                        <label className="block text-sm text-slate-400 mb-1">
                          Private key passphrase <span className="text-slate-500">(optional)</span>
                        </label>
                        <input
                          type="password"
                          value={formData.linux.privateKeyPassphrase}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              linux: { ...formData.linux, privateKeyPassphrase: e.target.value },
                            })
                          }
                          className={inputClass}
                          placeholder="Only if your private key is encrypted"
                        />
                      </div>
                    )}
                    <div>
                      <label className="block text-sm text-slate-400 mb-2">Log files to read *</label>
                      <div className="space-y-2">
                        {LINUX_LOG_PATH_OPTIONS.map(({ path, label, hint }) => (
                          <label key={path} className="flex items-start gap-2 text-sm cursor-pointer">
                            <input
                              type="checkbox"
                              checked={formData.linux.logPaths.includes(path)}
                              onChange={() => toggleLogPath(path)}
                              className="mt-0.5"
                            />
                            <span>
                              <span className="text-slate-300 font-mono text-xs">{label}</span>
                              <span className="text-slate-500 text-xs"> - {hint}</span>
                            </span>
                          </label>
                        ))}
                      </div>
                      {formData.linux.logPaths.length === 0 && (
                        <p className={fieldErrorClass}>Select at least one log file.</p>
                      )}
                    </div>
                  </div>
                </CollapsibleSection>

                <div className="p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                  <p className="text-xs text-blue-400">
                    Your username, password or key, and host key are encrypted before they're
                    stored and are never shown again after you submit. CyberGuard's server
                    connects to your Linux host over SSH - your browser never does.
                  </p>
                </div>
              </>
            )}

            {sourceType === 'android_adb' && (
              <>
                <p className="text-sm text-slate-400">
                  This connects to an Android device that's already plugged into (or already
                  paired over the network with) the CyberGuard server - not your own phone over
                  the internet. The device must already have "Allow USB debugging" accepted on it.
                </p>
                <div>
                  <label className="block text-sm text-slate-400 mb-1">Device Serial *</label>
                  <input
                    type="text"
                    required
                    value={formData.android.deviceSerial}
                    onChange={(e) =>
                      setFormData({ ...formData, android: { ...formData.android, deviceSerial: e.target.value } })
                    }
                    className={inputClass}
                    placeholder="e.g. emulator-5554 or ZY223JL4GF"
                  />
                  <p className="text-xs text-slate-500 mt-1">
                    Exact serial as shown by <code className="text-slate-400">adb devices -l</code> on
                    the backend host. This collector only collects from this exact device.
                  </p>
                </div>

                <CollapsibleSection title="Advanced / network device settings" icon={Smartphone}>
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm text-slate-400 mb-1">Network ADB Host (optional)</label>
                      <input
                        type="text"
                        value={formData.android.adbHost}
                        onChange={(e) =>
                          setFormData({ ...formData, android: { ...formData.android, adbHost: e.target.value } })
                        }
                        className={inputClass}
                        placeholder="Leave blank if the device is connected via USB"
                      />
                    </div>
                    {formData.android.adbHost && (
                      <div>
                        <label className="block text-sm text-slate-400 mb-1">ADB Port</label>
                        <input
                          type="number"
                          value={formData.android.adbPort}
                          onChange={(e) =>
                            setFormData({ ...formData, android: { ...formData.android, adbPort: e.target.value } })
                          }
                          className={inputClass}
                          placeholder="5555"
                        />
                      </div>
                    )}
                  </div>
                </CollapsibleSection>

                <div className="p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                  <p className="text-xs text-blue-400">
                    Requires <code className="text-blue-300">adb</code> installed on this backend
                    server, with the device already connected (USB, or network adb) and its "Allow
                    USB debugging" prompt already accepted on the device. This does not support
                    collecting from an arbitrary remote end user's personal phone - it's for a
                    lab/kiosk/on-prem device reachable from this server. Device authorization and
                    online state are verified before any collection starts.
                  </p>
                </div>
              </>
            )}

            {createMutation.error && (
              <div
                role="alert"
                aria-live="assertive"
                className="flex items-center gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-lg"
              >
                <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
                <p className="text-red-400 text-sm">
                  {(createMutation.error as any)?.response?.data?.detail || 'Failed to create source'}
                </p>
              </div>
            )}

            {/* Advisory only - runs the same real connect()/disconnect() (or
                device-state) probe the backend uses, against whatever is
                currently in the form, before any source row exists. Never
                blocks submission: a failed check doesn't disable "Add
                Source" since the admin may know something the probe
                can't see from here (e.g. a firewall rule that only applies
                to the backend's real network path). */}
            {checkMutation.data && (
              <div
                role="status"
                className={clsx(
                  'flex items-start gap-2 p-3 rounded-lg border text-sm',
                  checkMutation.data.ok
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                    : 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                )}
              >
                {checkMutation.data.ok ? (
                  <CheckCircle2 className="w-4 h-4 flex-shrink-0 mt-0.5" />
                ) : (
                  <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                )}
                <div className="min-w-0">
                  <p>{checkMutation.data.message}</p>
                  {checkMutation.data.detail && (
                    <p className="mt-1 text-xs opacity-80 break-words">{checkMutation.data.detail}</p>
                  )}
                </div>
              </div>
            )}
            {checkMutation.isError && (
              <p className="text-xs text-amber-400">
                Could not run the connection check.{' '}
                {(checkMutation.error as any)?.response?.data?.detail || 'Try again.'}
              </p>
            )}

            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setStep('type')}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors"
              >
                Back
              </button>
              <button
                type="button"
                onClick={() => checkMutation.mutate()}
                disabled={!canSubmit || checkMutation.isPending}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
              >
                {checkMutation.isPending && <RefreshCw className="w-4 h-4 animate-spin" />}
                Test connection
              </button>
              <button
                type="submit"
                disabled={!canSubmit || createMutation.isPending}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
              >
                {createMutation.isPending && <RefreshCw className="w-4 h-4 animate-spin" />}
                Add Source
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}

// ============================================================================
// Source Card
// ============================================================================

// Source types with an embedded collector that can actually be restarted
// via POST /logs/sources/{id}/restart (see backend/app/api/v1/logs.py).
// STEP 9: android_adb has an embedded collector too (AndroidADBCollector)
// and is restartable - useful after reconnecting/authorizing a device.
// STEP: local_network_monitor has an embedded collector too
// (LocalNetworkMonitorCollector) and is restartable the same way.
const RESTARTABLE_TYPES = new Set(['windows_event', 'linux_ssh', 'android_adb', 'local_network_monitor'])

export function SourceCard({
  source,
  onDelete,
}: {
  source: LogSourceResponse
  onDelete: (id: string) => void
}) {
  const [expanded, setExpanded] = useState(false)
  const queryClient = useQueryClient()

  const restartMutation = useMutation({
    mutationFn: () => logsApi.restartSource(source.id),
    onSuccess: () => {
      // The collector restarts asynchronously, so the status in the
      // immediate response may still read "error" for a moment - refetch
      // shortly after so the card picks up the real post-restart state.
      queryClient.invalidateQueries({ queryKey: ['log-sources'] })
      setTimeout(() => queryClient.invalidateQueries({ queryKey: ['log-sources'] }), 2500)
    },
  })

  const stopMutation = useMutation({
    mutationFn: () => logsApi.stopSource(source.id),
    onSuccess: () => {
      // Mirrors restartMutation's refetch pattern - the backend's own
      // stop route can return a 202 "still shutting down" response rather
      // than a confirmed stop, so a short delayed refetch picks up the
      // real post-stop state either way.
      queryClient.invalidateQueries({ queryKey: ['log-sources'] })
      setTimeout(() => queryClient.invalidateQueries({ queryKey: ['log-sources'] }), 2500)
    },
  })

  const checkConnMutation = useMutation({
    mutationFn: () => logsApi.checkConnection(source.id),
  })

  const typeIcons: Record<string, typeof Monitor> = {
    windows_event: Monitor,
    linux_ssh: Terminal,
    android_adb: Smartphone,
    local_network_monitor: Radar,
  }
  const Icon = typeIcons[source.source_type] || FileText

  const typeLabels: Record<string, string> = {
    windows_event: 'Windows Event Log',
    linux_ssh: 'Linux / SSH',
    android_adb: 'Android Device',
    local_network_monitor: 'This Computer (Local Monitor)',
  }

  // `collector_status` is the real, live CollectorManager telemetry - when
  // present it's a more current signal than the DB-persisted `status`
  // (which restart_log_source's own docs note can lag). It's null for
  // PENDING/DISABLED sources, HTTP_RECEIVER sources (no embedded
  // collector), or any source the backend hasn't re-started since its
  // last restart - never fabricated as a fake "stopped" state.
  const live = source.collector_status
  const isReconnecting = live?.state === 'reconnecting'
  const isLiveFailed = live?.state === 'failed'
  const isError = isLiveFailed || (!live && source.status?.toLowerCase() === 'error')
  // The dot/label shown in the header: prefer the live supervisor state
  // when we have one (it distinguishes "reconnecting" from a hard error),
  // otherwise fall back to today's DB-persisted status.
  const displayStatus = live ? live.state : source.status
  const canRestart = RESTARTABLE_TYPES.has(source.source_type)
  // A source with no events yet but a healthy status (active/pending) is
  // "waiting for data", not broken - distinguish that from a true
  // collector failure so analysts don't treat the two the same. When a
  // live supervisor is running, "waiting for data" means it's up but
  // hasn't logged a successful collection yet, which is a stronger signal
  // than just event_count === 0.
  const isWaitingForData = !isError && !isReconnecting && (
    live
      ? live.state === 'running' && !live.last_successful_collection_at
      : !source.event_count
  )

  return (
    <div
      className={clsx(
        'bg-slate-900 border rounded-xl overflow-hidden transition-colors',
        isError ? 'border-red-900/60' : isReconnecting ? 'border-amber-900/60' : 'border-slate-800'
      )}
    >
      <div className="p-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            <div className="p-2.5 bg-slate-800 rounded-lg flex-shrink-0">
              <Icon className="w-5 h-5 text-cyan-400" />
            </div>
            <div className="min-w-0">
              <p className="text-white font-medium truncate">{source.name}</p>
              <p className="text-xs text-slate-500">{typeLabels[source.source_type] || source.source_type}</p>
            </div>
          </div>
          <div className="flex items-center gap-3 flex-shrink-0">
            <StatusDot status={displayStatus} />
            {/* Always visible (not gated behind the expand toggle) so the
                automatic monitoring detection report is reachable without
                an extra click - previously this only rendered inside the
                `{expanded && ...}` section below and was invisible by
                default. */}
            <DetectionReportButton sourceId={source.id} sourceName={source.name} />
            <button
              onClick={() => setExpanded(!expanded)}
              className="p-1 text-slate-500 hover:text-white"
              aria-label={expanded ? 'Collapse source details' : 'Expand source details'}
              aria-expanded={expanded}
            >
              {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
            </button>
          </div>
        </div>

        <div className="mt-3 grid grid-cols-3 gap-3">
          <div className="bg-slate-800/50 rounded-lg p-2.5 text-center">
            <p className="text-lg font-bold text-white">{source.event_count?.toLocaleString() ?? '—'}</p>
            <p className="text-xs text-slate-500">Events</p>
          </div>
          <div className="bg-slate-800/50 rounded-lg p-2.5 text-center">
            <p className="text-sm text-white">{formatRelativeTime(source.last_event_at)}</p>
            <p className="text-xs text-slate-500">Last Event</p>
          </div>
          <div className="bg-slate-800/50 rounded-lg p-2.5 text-center">
            <p className="text-sm text-white truncate">
              {String(
                source.configuration?.computer_name ||
                  source.configuration?.hostname ||
                  source.configuration?.device_serial ||
                  'Local machine'
              )}
            </p>
            <p className="text-xs text-slate-500">{source.source_type === 'android_adb' ? 'Device' : 'Host'}</p>
          </div>
        </div>

        {isError && (live?.last_error || source.error_message) ? (
          <div className="mt-3 flex items-start gap-2 p-2.5 bg-red-500/10 border border-red-500/20 rounded-lg">
            <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
            <div className="min-w-0 flex-1">
              <p className="text-xs text-red-400 break-words">{live?.last_error || source.error_message}</p>
              <div className="mt-2 flex items-center gap-3">
                {canRestart && (
                  <button
                    onClick={() => restartMutation.mutate()}
                    disabled={restartMutation.isPending}
                    className="flex items-center gap-1.5 text-xs text-red-300 hover:text-white disabled:opacity-50"
                  >
                    <RefreshCw className={clsx('w-3.5 h-3.5', restartMutation.isPending && 'animate-spin')} />
                    {restartMutation.isPending ? 'Restarting…' : 'Retry collector'}
                  </button>
                )}
                {canRestart && (
                  <button
                    onClick={() => checkConnMutation.mutate()}
                    disabled={checkConnMutation.isPending}
                    className="flex items-center gap-1.5 text-xs text-red-300 hover:text-white disabled:opacity-50"
                  >
                    <ShieldCheck className={clsx('w-3.5 h-3.5', checkConnMutation.isPending && 'animate-pulse')} />
                    {checkConnMutation.isPending ? 'Checking…' : 'Check permissions'}
                  </button>
                )}
              </div>
              {checkConnMutation.data && (
                <div
                  role="status"
                  className={clsx(
                    'mt-2 text-xs rounded-md p-2 border',
                    checkConnMutation.data.ok
                      ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'
                      : 'text-amber-400 bg-amber-500/10 border-amber-500/20'
                  )}
                >
                  <p>{checkConnMutation.data.message}</p>
                  {checkConnMutation.data.detail && (
                    <p className="mt-1 opacity-80 break-words">{checkConnMutation.data.detail}</p>
                  )}
                </div>
              )}
              {checkConnMutation.isError && (
                <p className="mt-2 text-xs text-amber-400">
                  Could not run the check. {(checkConnMutation.error as any)?.response?.data?.detail || 'Try again.'}
                </p>
              )}
            </div>
          </div>
        ) : isReconnecting ? (
          <div className="mt-3 flex items-center gap-2 p-2.5 bg-amber-500/10 border border-amber-500/20 rounded-lg">
            <RefreshCw className="w-4 h-4 text-amber-400 flex-shrink-0 animate-spin" />
            <p className="text-xs text-amber-300">
              Reconnecting — the collector lost its connection and is retrying
              {live && live.reconnect_count > 0 ? ` (attempt ${live.reconnect_count})` : ''}.
            </p>
          </div>
        ) : isWaitingForData ? (
          <div className="mt-3 flex items-center gap-2 p-2 text-xs text-slate-500">
            <Activity className="w-3.5 h-3.5 flex-shrink-0" />
            {live
              ? "Waiting for events — the collector is running but hasn't completed a successful collection yet."
              : source.status === 'pending'
                ? 'Waiting for events — the source is starting up and has not reported in yet.'
                : "No live collector telemetry — last known status was \"" + source.status + "\". It may be running without having restarted since the last backend deploy, or it may have stopped silently."}
          </div>
        ) : null}

        {restartMutation.isError && (
          <p className="mt-2 text-xs text-red-400">
            Restart request failed. {(restartMutation.error as any)?.response?.data?.detail || 'Try again.'}
          </p>
        )}
        {stopMutation.isError && (
          <p className="mt-2 text-xs text-red-400">
            Stop request failed. {(stopMutation.error as any)?.response?.data?.detail || 'Try again.'}
          </p>
        )}
        {stopMutation.data && stopMutation.data.stop_confirmed === false && (
          <p className="mt-2 text-xs text-amber-400">
            Stop requested — the collector is still shutting down. Refresh in a moment to confirm.
          </p>
        )}
      </div>

      {expanded && (
        <div className="border-t border-slate-800 p-4 space-y-3">
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div>
              <p className="text-slate-500">Source ID</p>
              <p className="text-white font-mono truncate">{source.id}</p>
            </div>
            <div>
              <p className="text-slate-500">Created</p>
              <p className="text-white">{source.created_at ? new Date(source.created_at).toLocaleDateString() : '—'}</p>
            </div>
            {live ? (
              <>
                <div>
                  <p className="text-slate-500">Last Successful Collection</p>
                  <p className="text-white">{formatRelativeTime(live.last_successful_collection_at)}</p>
                </div>
                <div>
                  <p className="text-slate-500">Reconnects / Errors</p>
                  <p className="text-white">{live.reconnect_count} / {live.error_count}</p>
                </div>
              </>
            ) : (
              <div className="col-span-2">
                <p className="text-slate-500">Live Collector Telemetry</p>
                <p className="text-white">
                  Not available — no active collector supervisor is running for this
                  source right now (it may be pending, disabled, or awaiting restart).
                </p>
              </div>
            )}
            {source.source_type === 'android_adb' && (
              <>
                <div>
                  <p className="text-slate-500">Device Serial</p>
                  <p className="text-white font-mono truncate">{String(source.configuration?.device_serial || '—')}</p>
                </div>
                <div>
                  <p className="text-slate-500">Connection Method</p>
                  <p className="text-white">
                    {source.configuration?.adb_host
                      ? `Network ADB (${source.configuration.adb_host}:${source.configuration.adb_port ?? 5555})`
                      : 'USB'}
                  </p>
                </div>
                {/* There is no separate device-state/connection-status field
                    on LogSource.to_dict() (backend/app/logs/models.py) - the
                    backend surfaces device authorization/online state
                    through the source's own status + error_message
                    (AndroidADBCollector.connect() -> record_error() with a
                    specific explanation per DeviceState, e.g. "unauthorized"
                    or "offline"). That's already shown above via StatusDot
                    and the error banner - not duplicated here. */}
                <div className="col-span-2">
                  <p className="text-slate-500">Collection State</p>
                  <p className="text-white">
                    Reflected in the status indicator above. {canRestart && isError
                      ? 'Reconnect/authorize the device, then use Retry collector.'
                      : "A specific reason (e.g. device unauthorized or offline) appears here if collection fails."}
                  </p>
                </div>
              </>
            )}
          </div>
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              {isError && canRestart && (
                <button
                  onClick={() => restartMutation.mutate()}
                  disabled={restartMutation.isPending}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-cyan-400 hover:text-cyan-300 hover:bg-cyan-500/10 rounded-lg transition-colors disabled:opacity-50"
                >
                  <RefreshCw className={clsx('w-4 h-4', restartMutation.isPending && 'animate-spin')} />
                  Retry collector
                </button>
              )}
              {/* Only enabled when we have live confirmation the collector
                  is actually running - stopping a source with no live
                  supervisor would just hit the backend's own 400, since
                  there's nothing real to stop. */}
              {canRestart && live && live.state === 'running' && (
                <button
                  onClick={() => stopMutation.mutate()}
                  disabled={stopMutation.isPending}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-amber-400 hover:text-amber-300 hover:bg-amber-500/10 rounded-lg transition-colors disabled:opacity-50"
                >
                  <XCircle className={clsx('w-4 h-4', stopMutation.isPending && 'animate-pulse')} />
                  {stopMutation.isPending ? 'Stopping…' : 'Stop collector'}
                </button>
              )}
              {canRestart && (
                <button
                  onClick={() => checkConnMutation.mutate()}
                  disabled={checkConnMutation.isPending}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors disabled:opacity-50"
                >
                  <ShieldCheck className={clsx('w-4 h-4', checkConnMutation.isPending && 'animate-pulse')} />
                  {checkConnMutation.isPending ? 'Checking…' : 'Check permissions'}
                </button>
              )}
            </div>
            <button
              onClick={() => onDelete(source.id)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded-lg transition-colors"
            >
              <Trash2 className="w-4 h-4" />
              Remove Source
            </button>
          </div>
          {checkConnMutation.data && (
            <div
              role="status"
              className={clsx(
                'text-xs rounded-md p-2 border',
                checkConnMutation.data.ok
                  ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'
                  : 'text-amber-400 bg-amber-500/10 border-amber-500/20'
              )}
            >
              <p>{checkConnMutation.data.message}</p>
              {checkConnMutation.data.detail && (
                <p className="mt-1 opacity-80 break-words">{checkConnMutation.data.detail}</p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ============================================================================
// Log Events Tab
// ============================================================================

const EVENTS_PAGE_SIZE = 50

// Lookback windows for the time-range filter. Sent to the backend as
// start_time (an ISO timestamp relative to "now"), which GET /logs/events
// genuinely supports (see LogEventQuery.start_time) - this is a real
// filter, not a client-side slice of an already-fetched page.
const TIME_RANGES = [
  { id: '1h', label: 'Last hour', ms: 60 * 60 * 1000 },
  { id: '24h', label: 'Last 24 hours', ms: 24 * 60 * 60 * 1000 },
  { id: '7d', label: 'Last 7 days', ms: 7 * 24 * 60 * 60 * 1000 },
  { id: 'all', label: 'All time', ms: null as number | null },
]

function EventDetailPanel({ event, onClose }: { event: any; onClose: () => void }) {
  const [view, setView] = useState<'normalized' | 'raw'>('normalized')
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-end z-50">
      <div className="bg-slate-900 border-l border-slate-800 w-full max-w-lg h-full overflow-y-auto">
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between sticky top-0 bg-slate-900">
          <div>
            <h2 className="text-lg font-semibold text-white">Event Detail</h2>
            <p className="text-xs text-slate-500 font-mono mt-0.5">{event.id}</p>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white">
            <XCircle className="w-5 h-5" />
          </button>
        </div>
        <div className="p-6 space-y-4">
          <div className="flex items-center gap-3">
            <SeverityBadge severity={event.level || 'info'} />
            <span className="text-sm text-slate-400">
              {event.timestamp ? new Date(event.timestamp).toLocaleString() : '—'}
            </span>
          </div>

          <div className="flex gap-1 border-b border-slate-800">
            {(['normalized', 'raw'] as const).map((v) => (
              <button
                key={v}
                onClick={() => setView(v)}
                className={clsx(
                  'px-3 py-2 text-sm font-medium border-b-2 -mb-px transition-colors',
                  view === v ? 'text-cyan-400 border-cyan-400' : 'text-slate-400 border-transparent hover:text-slate-300'
                )}
              >
                {v === 'normalized' ? 'Normalized' : 'Raw'}
              </button>
            ))}
          </div>

          {view === 'normalized' ? (
            <div className="space-y-3 text-sm">
              {[
                ['Source Type', event.source_type],
                ['Hostname', event.hostname],
                ['Program', event.program],
                ['Category', event.category],
                ['Message', event.message],
              ].map(([label, value]) => (
                <div key={label}>
                  <p className="text-slate-500 text-xs uppercase tracking-wider mb-0.5">{label}</p>
                  <p className="text-slate-200 break-words">{value || '—'}</p>
                </div>
              ))}
              {event.extracted_fields && Object.keys(event.extracted_fields).length > 0 && (
                <div>
                  <p className="text-slate-500 text-xs uppercase tracking-wider mb-1">Extracted Fields</p>
                  <div className="bg-slate-800/50 rounded-lg p-3 space-y-1">
                    {Object.entries(event.extracted_fields).map(([k, v]) => (
                      <div key={k} className="flex gap-2 text-xs">
                        <span className="text-slate-500 font-mono">{k}:</span>
                        <span className="text-slate-300 font-mono break-all">{String(v)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {event.risk_indicators && event.risk_indicators.length > 0 && (
                <div>
                  <p className="text-slate-500 text-xs uppercase tracking-wider mb-1">Risk Indicators</p>
                  <div className="flex flex-wrap gap-1.5">
                    {event.risk_indicators.map((ind: string, i: number) => (
                      <span key={i} className="px-2 py-0.5 text-xs bg-orange-500/15 text-orange-400 rounded">{ind}</span>
                    ))}
                  </div>
                </div>
              )}
              {/* Related alerts/incidents: the backend has no endpoint that
                  joins a LogEvent to the alerts/incidents it may have
                  triggered (LogEvent only stores correlation_id and
                  analysis_result_id, with no reverse lookup API) - rather
                  than fake a link, this is surfaced as a known gap. */}
              <div className="p-3 bg-slate-800/30 border border-slate-800 rounded-lg">
                <p className="text-xs text-slate-500">
                  Related alerts and incidents aren't available yet — the backend doesn't expose a lookup from a log event to the alerts/incidents it may have triggered.
                </p>
              </div>
            </div>
          ) : (
            <pre className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs text-slate-300 whitespace-pre-wrap break-all font-mono max-h-96 overflow-y-auto">
              {event.raw_content || event.message || '—'}
            </pre>
          )}
        </div>
      </div>
    </div>
  )
}

function LogEventsTab() {
  const [filters, setFilters] = useState({
    source_id: '',
    level: '',
    hostname: '',
    category: '',
    search: '',
    range: '24h',
  })
  const [offset, setOffset] = useState(0)
  const [selectedEvent, setSelectedEvent] = useState<any>(null)

  const { data: sourcesData } = useQuery({
    queryKey: ['log-sources'],
    queryFn: () => logsApi.listSources({ limit: 100 }),
  })

  const range = TIME_RANGES.find((r) => r.id === filters.range) ?? TIME_RANGES[1]
  const startTime = range.ms ? new Date(Date.now() - range.ms).toISOString() : undefined

  const { data, isLoading, isFetching, error, refetch } = useQuery({
    queryKey: ['log-events', filters, offset],
    queryFn: () => logsApi.listEvents({
      source_id: filters.source_id || undefined,
      level: filters.level || undefined,
      hostname: filters.hostname || undefined,
      category: filters.category || undefined,
      search: filters.search.length >= 2 ? filters.search : undefined,
      start_time: startTime,
      limit: EVENTS_PAGE_SIZE,
      offset,
    }),
    refetchInterval: 30000,
  })

  const events = data?.events || []
  const total = data?.total ?? events.length
  const hasNextPage = offset + EVENTS_PAGE_SIZE < total

  const updateFilter = (patch: Partial<typeof filters>) => {
    setOffset(0)
    setFilters((f) => ({ ...f, ...patch }))
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-3">
        <select
          value={filters.source_id}
          onChange={(e) => updateFilter({ source_id: e.target.value })}
          className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 text-sm"
        >
          <option value="">All Sources</option>
          {(sourcesData?.sources || []).map((s: any) => (
            <option key={s.id} value={s.id}>{s.name}</option>
          ))}
        </select>
        <select
          value={filters.level}
          onChange={(e) => updateFilter({ level: e.target.value })}
          className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 text-sm"
        >
          <option value="">All Levels</option>
          <option value="critical">Critical</option>
          <option value="error">Error</option>
          <option value="warning">Warning</option>
          <option value="info">Info</option>
          <option value="debug">Debug</option>
        </select>
        <select
          value={filters.range}
          onChange={(e) => updateFilter({ range: e.target.value })}
          className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 text-sm"
        >
          {TIME_RANGES.map((r) => (
            <option key={r.id} value={r.id}>{r.label}</option>
          ))}
        </select>
        <input
          type="text"
          value={filters.hostname}
          onChange={(e) => updateFilter({ hostname: e.target.value })}
          placeholder="Hostname..."
          className="w-32 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 text-sm"
        />
        <input
          type="text"
          value={filters.search}
          onChange={(e) => updateFilter({ search: e.target.value })}
          placeholder="Search log messages... (min 2 chars)"
          className="flex-1 min-w-[200px] bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 text-sm"
        />
        <button
          onClick={() => refetch()}
          className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors"
          aria-label="Refresh events"
        >
          <RefreshCw className={clsx('w-4 h-4', isFetching && 'animate-spin')} />
        </button>
      </div>

      {error ? (
        <div className="flex items-center gap-2 p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
          <XCircle className="w-5 h-5 text-red-400" />
          <p className="text-red-400 text-sm">Unable to load log events</p>
          <button onClick={() => refetch()} className="ml-auto text-sm text-red-400 hover:text-red-300 underline">Retry</button>
        </div>
      ) : isLoading ? (
        <div className="flex items-center justify-center py-12">
          <RefreshCw className="w-6 h-6 text-slate-500 animate-spin" />
        </div>
      ) : events.length === 0 ? (
        <div className="p-12 text-center bg-slate-900 border border-slate-800 rounded-xl">
          <FileText className="w-12 h-12 text-slate-700 mx-auto mb-3" />
          <p className="text-slate-500">No log events found</p>
          <p className="text-sm text-slate-600 mt-1">
            {filters.source_id || filters.level || filters.hostname || filters.search
              ? 'Try widening your filters or time range.'
              : "Add a log source and start collecting events."}
          </p>
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Time</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Level</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Source</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Host</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Message</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {events.map((ev: any) => (
                  <tr
                    key={ev.id}
                    onClick={() => setSelectedEvent(ev)}
                    tabIndex={0}
                    role="button"
                    onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') setSelectedEvent(ev) }}
                    className="hover:bg-slate-800/50 transition-colors cursor-pointer focus:bg-slate-800/70 focus:outline-none"
                  >
                    <td className="px-4 py-3 text-slate-400 whitespace-nowrap">
                      {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : '—'}
                    </td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={ev.level || 'info'} />
                    </td>
                    <td className="px-4 py-3 text-slate-300">{ev.source_type || '—'}</td>
                    <td className="px-4 py-3 text-slate-300">{ev.hostname || '—'}</td>
                    <td className="px-4 py-3 text-slate-300 max-w-xs truncate">{ev.message || ev.raw_content || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="px-4 py-3 border-t border-slate-800 flex items-center justify-between text-sm text-slate-500">
            <span>
              Showing {offset + 1}–{offset + events.length} of {total.toLocaleString()} events
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setOffset(Math.max(0, offset - EVENTS_PAGE_SIZE))}
                disabled={offset === 0}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800 text-slate-300 rounded-lg transition-colors text-xs"
              >
                Previous
              </button>
              <button
                onClick={() => setOffset(offset + EVENTS_PAGE_SIZE)}
                disabled={!hasNextPage}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800 text-slate-300 rounded-lg transition-colors text-xs"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      )}

      {selectedEvent && (
        <EventDetailPanel event={selectedEvent} onClose={() => setSelectedEvent(null)} />
      )}
    </div>
  )
}

// ============================================================================
// Manual Analysis Tab (dev/troubleshooting)
// ============================================================================

type LogSourceTypeHint = 'windows' | 'linux_ssh' | 'android' | 'auto'

const LOG_SOURCE_TYPE_HINTS: { id: LogSourceTypeHint; label: string }[] = [
  { id: 'auto', label: 'Auto-detect' },
  { id: 'windows', label: 'Windows' },
  { id: 'linux_ssh', label: 'Linux / SSH' },
  { id: 'android', label: 'Android' },
]

/** Human-readable mapping for POST /analysis/logs/upload error responses
 * (400/401/409/413/5xx) - mirrors EmailAnalysisPage's UploadTab error
 * mapping convention for the sibling .eml upload flow. */
function uploadErrorMessage(error: any): string {
  const status = error?.response?.status
  const detail = error?.response?.data?.detail
  if (status === 401) return 'You need to be signed in to upload log files.'
  if (status === 409) return detail || 'This exact file was already submitted recently. Wait a moment before retrying.'
  if (status === 413) return detail || 'File is too large.'
  if (status === 400) return detail || 'The file could not be parsed.'
  if (error?.code === 'ECONNABORTED') return 'The request timed out. Try a smaller file.'
  return detail || 'Upload failed. Please try again.'
}

/** File-upload sibling to the paste-based Manual Analysis form, mounted
 * via the Paste/Upload toggle below. Preview-fetches parsed events on
 * file selection (preview_only=true, no LogAgent dispatch), then runs
 * the real analysis (reusing the same results panel as paste mode) when
 * the user clicks Analyze. */
function LogFileUploadPanel({ onResult }: { onResult: (result: any | null) => void }) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [fileError, setFileError] = useState<string | null>(null)
  const [sourceTypeHint, setSourceTypeHint] = useState<LogSourceTypeHint>('auto')
  const [uploadProgress, setUploadProgress] = useState(0)

  const previewMutation = useMutation({
    mutationFn: (file: File) => analysisApi.uploadLogFile(file, sourceTypeHint, { previewOnly: true }),
  })

  const analyzeMutation = useMutation({
    mutationFn: () => {
      if (!selectedFile) throw new Error('No file selected')
      setUploadProgress(0)
      return analysisApi.uploadLogFile(selectedFile, sourceTypeHint, {
        onProgress: setUploadProgress,
      })
    },
    onSuccess: (data) => onResult(data),
  })

  const handleFileSelected = (file: File) => {
    setSelectedFile(file)
    setFileError(null)
    onResult(null)
    previewMutation.mutate(file)
  }

  const handleClear = () => {
    setSelectedFile(null)
    setFileError(null)
    onResult(null)
    previewMutation.reset()
    analyzeMutation.reset()
  }

  const preview = previewMutation.data

  return (
    <div className="p-6 space-y-4">
      <div>
        <label className="block text-sm text-slate-400 mb-1">Log Source Type</label>
        <select
          value={sourceTypeHint}
          onChange={(e) => setSourceTypeHint(e.target.value as LogSourceTypeHint)}
          disabled={analyzeMutation.isPending}
          className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 disabled:opacity-50"
        >
          {LOG_SOURCE_TYPE_HINTS.map(({ id, label }) => (
            <option key={id} value={id}>{label}</option>
          ))}
        </select>
        {sourceTypeHint === 'windows' && (
          <p className="text-xs text-slate-500 mt-1">
            Full fidelity requires exported Event Log XML. Other Windows text falls back to a best-effort generic parser.
          </p>
        )}
      </div>

      <LogFileDropzone
        selectedFile={selectedFile}
        error={fileError}
        disabled={analyzeMutation.isPending}
        onFileSelected={handleFileSelected}
        onError={setFileError}
        onClear={handleClear}
      />

      {previewMutation.isPending && (
        <div className="flex items-center gap-2 text-sm text-slate-400">
          <RefreshCw className="w-4 h-4 animate-spin" />
          Parsing file for preview...
        </div>
      )}

      {previewMutation.isError && (
        <div className="flex items-center gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
          <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
          <p className="text-red-400 text-sm">{uploadErrorMessage(previewMutation.error)}</p>
        </div>
      )}

      {preview && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-3 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>
              Detected: <span className="text-slate-200">{preview.detected_source_type}</span>
            </span>
            <span>{preview.parsed_event_count} parsed{preview.skipped_line_count > 0 ? `, ${preview.skipped_line_count} skipped` : ''}</span>
          </div>
          {preview.detected_source_type === 'windows_generic_fallback' && (
            <p className="text-xs text-yellow-400">
              Best-effort parse - export as Event Log XML for full Windows fidelity.
            </p>
          )}
          {preview.encoding_fallback_used && (
            <p className="text-xs text-yellow-400">File encoding fallback was used - some characters may be substituted.</p>
          )}
          {preview.preview_events?.length > 0 && (
            <div className="max-h-32 overflow-y-auto space-y-1">
              {preview.preview_events.slice(0, 5).map((ev: any, i: number) => (
                <p key={i} className="text-xs text-slate-400 font-mono truncate">
                  {ev.message || ev.raw_line || JSON.stringify(ev)}
                </p>
              ))}
            </div>
          )}
        </div>
      )}

      {analyzeMutation.isPending && (
        <div className="space-y-1">
          <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
            <div className="h-full bg-cyan-500 transition-all" style={{ width: `${uploadProgress}%` }} />
          </div>
          <p className="text-xs text-slate-500">Uploading... {uploadProgress}%</p>
        </div>
      )}

      <div className="flex gap-3">
        <button
          type="button"
          onClick={() => analyzeMutation.mutate()}
          disabled={!selectedFile || !!fileError || analyzeMutation.isPending || previewMutation.isPending}
          className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors disabled:opacity-50"
        >
          {analyzeMutation.isPending ? <><RefreshCw className="w-4 h-4 animate-spin" />Analyzing...</> : <><Send className="w-4 h-4" />Analyze Log File</>}
        </button>
        <button
          type="button"
          onClick={handleClear}
          disabled={analyzeMutation.isPending}
          className="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors disabled:opacity-50"
        >
          Reset
        </button>
      </div>

      {analyzeMutation.isError && (
        <div className="flex items-center gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
          <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
          <p className="text-red-400 text-sm">{uploadErrorMessage(analyzeMutation.error)}</p>
        </div>
      )}
    </div>
  )
}

function ManualAnalysisTab() {
  const [inputMode, setInputMode] = useState<'paste' | 'upload'>('paste')
  const [logText, setLogText] = useState('')
  const [source, setSource] = useState('system')
  const [result, setResult] = useState<any>(null)

  const analyzeMutation = useMutation({
    mutationFn: () => analysisApi.analyzeLogs({ log_content: logText, log_type: source, source }),
    onSuccess: (data) => setResult(data),
  })

  const loadSampleLogs = () => {
    setLogText(`2024-03-15 10:23:45 ERROR Authentication failed for user admin from IP 192.168.1.100
2024-03-15 10:23:46 ERROR Authentication failed for user admin from IP 192.168.1.100
2024-03-15 10:23:47 ERROR Authentication failed for user admin from IP 192.168.1.100
2024-03-15 10:23:48 ERROR Authentication failed for user admin from IP 192.168.1.100
2024-03-15 10:23:49 ERROR Authentication failed for user admin from IP 192.168.1.100
2024-03-15 10:23:50 WARNING Multiple failed login attempts detected - possible brute force attack
2024-03-15 10:24:01 ERROR SQL injection attempt detected: SELECT * FROM users WHERE id=1 OR 1=1
2024-03-15 10:24:15 WARNING Suspicious file access: /etc/passwd
2024-03-15 10:24:30 ERROR Privilege escalation attempt by user guest
2024-03-15 10:24:45 CRITICAL Malware signature detected: trojan.generic.12345`)
    setSource('security')
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg">
        <p className="text-amber-400 text-sm">
          Ad-hoc analysis only — results here are never saved as Log Events and never affect dashboard statistics, even on a successful run. Use the Log Sources tab to collect events that persist.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
            <h3 className="font-semibold text-white flex items-center gap-2">
              <FileText className="w-4 h-4 text-cyan-400" />
              Log Input
            </h3>
            <div className="flex items-center gap-2">
              {inputMode === 'paste' && (
                <button
                  onClick={loadSampleLogs}
                  className="px-3 py-1.5 bg-purple-900/50 hover:bg-purple-900 border border-purple-700 text-purple-300 rounded-lg transition-colors text-xs"
                >
                  Load Sample Logs
                </button>
              )}
              <div className="flex gap-1 bg-slate-800 border border-slate-700 rounded-lg p-0.5">
                <button
                  type="button"
                  onClick={() => { setInputMode('paste'); setResult(null) }}
                  className={clsx(
                    'flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-md transition-colors',
                    inputMode === 'paste' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
                  )}
                >
                  <Clipboard className="w-3.5 h-3.5" />
                  Paste
                </button>
                <button
                  type="button"
                  onClick={() => { setInputMode('upload'); setResult(null) }}
                  className={clsx(
                    'flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-md transition-colors',
                    inputMode === 'upload' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
                  )}
                >
                  <Upload className="w-3.5 h-3.5" />
                  Upload
                </button>
              </div>
            </div>
          </div>

          {inputMode === 'upload' ? (
            <LogFileUploadPanel onResult={setResult} />
          ) : (
            <form onSubmit={(e) => { e.preventDefault(); setResult(null); analyzeMutation.mutate() }} className="p-6 space-y-4">
              <div>
                <label className="block text-sm text-slate-400 mb-1">Log Source Type</label>
                <select
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                >
                  <option value="system">System Logs</option>
                  <option value="security">Security Logs</option>
                  <option value="application">Application Logs</option>
                  <option value="firewall">Firewall Logs</option>
                  <option value="access">Access Logs</option>
                  <option value="audit">Audit Logs</option>
                </select>
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1">Log Content *</label>
                <textarea
                  required
                  value={logText}
                  onChange={(e) => setLogText(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 h-64 resize-none font-mono text-sm"
                  placeholder="Paste log entries here..."
                />
                <p className="text-xs text-slate-500 mt-1">
                  {logText.split('\n').filter((l) => l.trim()).length} lines
                </p>
              </div>
              <div className="flex gap-3">
                <button
                  type="submit"
                  disabled={analyzeMutation.isPending}
                  className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors disabled:opacity-50"
                >
                  {analyzeMutation.isPending ? <><RefreshCw className="w-4 h-4 animate-spin" />Analyzing...</> : <><Send className="w-4 h-4" />Analyze Logs</>}
                </button>
                <button type="button" onClick={() => { setLogText(''); setResult(null) }} className="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors">
                  Reset
                </button>
              </div>
              {analyzeMutation.error && (
                <div className="flex items-center gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                  <XCircle className="w-4 h-4 text-red-400" />
                  <p className="text-red-400 text-sm">Analysis failed. Please try again.</p>
                </div>
              )}
            </form>
          )}
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl">
          <div className="px-6 py-4 border-b border-slate-800">
            <h3 className="font-semibold text-white flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              Analysis Results
            </h3>
          </div>
          <div className="p-6">
            {!result ? (
              <div className="text-center py-12">
                <FileText className="w-16 h-16 text-slate-700 mx-auto mb-4" />
                <p className="text-slate-500">Submit logs to see analysis results</p>
              </div>
            ) : (
              <div className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg">
                <div>
                  <p className="text-white font-medium">Analysis complete</p>
                  <p className="text-sm text-slate-400">Full report below</p>
                </div>
                <SeverityBadge severity={result.severity || 'info'} />
              </div>
            )}
          </div>
        </div>
      </div>

      {result && <AnalysisReport result={result} />}
    </div>
  )
}

// ============================================================================
// Analysis Report (structured results panel for ManualAnalysisTab)
// ============================================================================
//
// Renders only fields the backend actually returns (AnalysisResponse /
// FindingResponse, app/schemas/analysis.py). Nothing here is fabricated:
// - source_ip/host/timestamp per finding are None when the underlying log
//   line didn't carry them (e.g. sudo lines have no IP) - rendered as "—".
// - Module Performance shows real facts: LogAgent is a rule engine with no
//   supervised accuracy/precision/recall/F1 computed anywhere in the
//   codebase - stated as such rather than inventing numbers.
// - Recommended Actions renders the real recommendations list as a plain
//   numbered list - no "High/Medium Priority" labels, since the backend
//   doesn't rank them.

/**
 * Confirm / False Positive feedback for a log analysis result. Mirrors
 * FeedbackActions in EmailInvestigationReport/FeedbackExportBar.tsx (same
 * mutation/toast/submitted-state shape) but with log-appropriate labels and
 * feedback types: "confirmed" (finding was reviewed and is correct) and
 * "false_positive" (finding was flagged but is actually benign). This is
 * one feedback action per analysis result, not per individual finding.
 */
function LogFeedbackActions({ analysisId }: { analysisId: string }) {
  const toast = useToast()
  const [submittedType, setSubmittedType] = useState<'confirmed' | 'false_positive' | null>(null)

  const mutation = useMutation({
    mutationFn: (feedback_type: 'confirmed' | 'false_positive') =>
      feedbackApi.submit({ analysis_id: analysisId, feedback_type }),
    onSuccess: (_data, feedback_type) => {
      setSubmittedType(feedback_type)
      toast.success('Feedback submitted', 'Thanks - this helps track LogAgent accuracy.')
    },
    onError: (error: any) => {
      const status = error?.response?.status
      const detail = error?.response?.data?.detail || error?.response?.data?.message
      if (status === 400 && detail?.toLowerCase().includes('duplicate')) {
        toast.warning('Already submitted', 'You already reported this result.')
      } else if (status === 401) {
        toast.error('Sign in required', 'Log in to submit feedback on this analysis.')
      } else {
        toast.error('Feedback failed', detail || 'Could not submit feedback. Please try again.')
      }
    },
  })

  if (submittedType) {
    return (
      <div className="flex items-center gap-2 text-sm text-emerald-400">
        <CheckCircle2 className="w-4 h-4" />
        {submittedType === 'confirmed' ? 'Marked as confirmed' : 'Reported as false positive'}
      </div>
    )
  }

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <span className="text-xs text-slate-500 mr-1">Were these findings correct?</span>
      <button
        onClick={() => mutation.mutate('confirmed')}
        disabled={mutation.isPending}
        title="These findings are correct"
        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors disabled:opacity-50"
      >
        <ThumbsUp className="w-3.5 h-3.5" />
        Confirm
      </button>
      <button
        onClick={() => mutation.mutate('false_positive')}
        disabled={mutation.isPending}
        title="These findings were flagged but are actually benign"
        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors disabled:opacity-50"
      >
        <ThumbsDown className="w-3.5 h-3.5" />
        False Positive
      </button>
    </div>
  )
}

function AnalysisReport({ result }: { result: any }) {
  const findings: any[] = result.findings || []
  const riskScore = result.risk_score ?? 0
  const affectedSystems: string[] = result.affected_systems || []
  const affectedAccounts: string[] = result.affected_accounts || []

  // Real, feedback-derived accuracy for LogAgent. accuracy_percent stays
  // null (rendered as "no feedback yet") until real feedback exists -
  // never defaulted to 0% or fabricated.
  const { data: moduleAccuracy } = useQuery({
    queryKey: ['logModuleAccuracy'],
    queryFn: () => feedbackApi.getLogModuleAccuracy(),
    staleTime: 30_000,
  })

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h3 className="text-lg font-semibold text-white flex items-center gap-2">
              <Search className="w-5 h-5 text-cyan-400" />
              Analysis Results
            </h3>
            <p className="text-sm text-slate-400 mt-0.5">Log security assessment completed</p>
          </div>
          <div className={clsx(
            'flex items-center gap-2 px-4 py-2 rounded-lg border',
            riskScore >= 75 ? 'bg-red-500/10 border-red-500/40 text-red-400'
              : riskScore >= 50 ? 'bg-orange-500/10 border-orange-500/40 text-orange-400'
              : riskScore >= 25 ? 'bg-yellow-500/10 border-yellow-500/40 text-yellow-400'
              : 'bg-emerald-500/10 border-emerald-500/40 text-emerald-400'
          )}>
            <Shield className="w-4 h-4" />
            <div>
              <p className="text-xs font-semibold">{riskLabel(riskScore)}</p>
              <p className="text-[11px] opacity-80">Based on detected findings</p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-x-5 gap-y-1 flex-wrap mt-4 text-xs text-slate-400">
          {result.result_id && (
            <span className="flex items-center gap-1.5"><Hash className="w-3.5 h-3.5" />Analysis ID: {result.result_id}</span>
          )}
          {result.started_at && (
            <span className="flex items-center gap-1.5"><Clock className="w-3.5 h-3.5" />{new Date(result.started_at).toLocaleString()}</span>
          )}
          {result.source && (
            <span className="flex items-center gap-1.5"><FileText className="w-3.5 h-3.5" />Source: {result.source}</span>
          )}
          {typeof result.processed_event_count === 'number' && (
            <span className="flex items-center gap-1.5"><Server className="w-3.5 h-3.5" />Processed: {result.processed_event_count.toLocaleString()} log entries</span>
          )}
          {typeof result.processing_time_ms === 'number' && (
            <span className="flex items-center gap-1.5"><Activity className="w-3.5 h-3.5" />Duration: {(result.processing_time_ms / 1000).toFixed(1)}s</span>
          )}
        </div>
      </div>

      {/* Stat tiles */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <StatTile
          icon={<FileText className="w-5 h-5 text-cyan-400" />}
          label="Total Findings"
          value={findings.length}
          sublabel="security issues detected"
        />
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
          <RiskGauge score={riskScore} />
          <div>
            <p className="text-xs text-slate-500 flex items-center gap-1">Risk Score</p>
            <p className="text-[11px] text-slate-500">Based on severity, frequency and context</p>
          </div>
        </div>
        <StatTile
          icon={<Monitor className="w-5 h-5 text-emerald-400" />}
          label="Affected Systems"
          value={affectedSystems.length}
          sublabel={affectedSystems[0] || undefined}
        />
        <StatTile
          icon={<Users className="w-5 h-5 text-purple-400" />}
          label="Affected Accounts"
          value={affectedAccounts.length}
          sublabel={affectedAccounts.length > 0 ? 'user account(s)' : undefined}
        />
        <StatTile
          icon={<Gauge className="w-5 h-5 text-cyan-400" />}
          label="Result Confidence"
          value={typeof result.confidence === 'number' ? `${Math.round(result.confidence * 100)}%` : '—'}
          sublabel="rule-based heuristic, not a calibrated probability"
        />
      </div>

      {/* Findings table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl">
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h3 className="font-semibold text-white flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-cyan-400" />
              Detected Security Findings
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">The following security issues were detected in the analyzed logs.</p>
          </div>
          <button
            onClick={() => exportReport(result)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors text-xs"
          >
            <Download className="w-3.5 h-3.5" />
            Export Report
          </button>
        </div>
        {findings.length > 0 && result.result_id && (
          <div className="px-6 py-3 border-b border-slate-800 bg-slate-800/30">
            <LogFeedbackActions analysisId={result.result_id} />
          </div>
        )}
        {findings.length === 0 ? (
          <div className="p-6 text-center text-slate-500 text-sm">No findings detected.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-slate-500 border-b border-slate-800">
                  <th className="px-4 py-2 font-medium">#</th>
                  <th className="px-4 py-2 font-medium">Finding</th>
                  <th className="px-4 py-2 font-medium">Severity</th>
                  <th className="px-4 py-2 font-medium">Description</th>
                  <th className="px-4 py-2 font-medium">Source</th>
                  <th className="px-4 py-2 font-medium">Evidence</th>
                  <th className="px-4 py-2 font-medium">Rule ID</th>
                  <th className="px-4 py-2 font-medium">Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f: any, i: number) => (
                  <tr key={f.finding_id || i} className="border-b border-slate-800/60 last:border-0">
                    <td className="px-4 py-3 text-slate-500">{i + 1}</td>
                    <td className="px-4 py-3 text-white font-medium whitespace-nowrap">{f.name}</td>
                    <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                    <td className="px-4 py-3 text-slate-400 max-w-xs">{f.description}</td>
                    <td className="px-4 py-3 text-slate-400 whitespace-nowrap">{f.source_ip || '—'}</td>
                    <td className="px-4 py-3 text-slate-400 max-w-xs">
                      {f.evidence?.length ? f.evidence[0] + (f.evidence.length > 1 ? ` (+${f.evidence.length - 1} more)` : '') : '—'}
                    </td>
                    <td className="px-4 py-3 text-slate-500 whitespace-nowrap font-mono text-xs">{f.rule_id || '—'}</td>
                    <td className="px-4 py-3 text-slate-500 whitespace-nowrap">{f.timestamp || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Module Performance + Recommended Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl">
          <div className="px-6 py-4 border-b border-slate-800">
            <h3 className="font-semibold text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Module Performance
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">Detection modules used for this analysis</p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-slate-500 border-b border-slate-800">
                  <th className="px-4 py-2 font-medium">Module</th>
                  <th className="px-4 py-2 font-medium">Evaluation</th>
                  <th className="px-4 py-2 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td className="px-4 py-3 text-white flex items-center gap-2">
                    <Shield className="w-3.5 h-3.5 text-cyan-400" />
                    LogAgent (Rule Engine)
                  </td>
                  <td className="px-4 py-3 text-slate-400">
                    {!moduleAccuracy || moduleAccuracy.confirmed_count + moduleAccuracy.false_positive_count === 0 ? (
                      <>No feedback yet — {moduleAccuracy?.total_analyses ?? 0} analyses run, 0 reviewed</>
                    ) : (
                      <>
                        {moduleAccuracy.confirmed_count} of {moduleAccuracy.confirmed_count + moduleAccuracy.false_positive_count} reviewed
                        findings confirmed ({moduleAccuracy.accuracy_percent}%)
                      </>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-0.5 text-xs font-medium rounded-md bg-emerald-500/20 text-emerald-400">Active</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div className="m-4 p-3 bg-slate-800/50 border border-slate-700 rounded-lg flex items-start gap-2">
            <Info className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
            <p className="text-xs text-slate-400">
              About Module Accuracy: this is a real, feedback-derived signal, not a supervised benchmark. It
              reflects the ratio of "Confirm" to "False Positive" feedback submitted by analysts below, so it
              starts sparse and grows more reliable as more analyses are reviewed.
            </p>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl">
          <div className="px-6 py-4 border-b border-slate-800">
            <h3 className="font-semibold text-white flex items-center gap-2">
              <Lightbulb className="w-4 h-4 text-cyan-400" />
              Recommended Actions
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">Based on detected findings</p>
          </div>
          <div className="p-4">
            {!result.recommendations || result.recommendations.length === 0 ? (
              <p className="text-sm text-slate-500">No specific actions recommended.</p>
            ) : (
              <ol className="space-y-3">
                {result.recommendations.map((r: string, i: number) => (
                  <li key={i} className="flex items-start gap-3">
                    <span className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-400 text-xs font-semibold flex items-center justify-center flex-shrink-0">
                      {i + 1}
                    </span>
                    <p className="text-sm text-slate-300 pt-0.5">{r}</p>
                  </li>
                ))}
              </ol>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// ============================================================================
// Source Health Overview
// ============================================================================

// Uses the shared SEVERITY_COLORS from '@/components/ui' (imported above)
// so this chart's bar colors can never drift from SeverityBadge's colors.

/**
 * Health summary + ingestion-by-severity chart for the Sources tab.
 *
 * Counts are derived from the already-fetched `sources` list (no extra
 * request). The chart uses GET /logs/events/statistics (real
 * backend-aggregated counts for the last 24h, see
 * backend/app/api/v1/logs.py get_log_statistics) - not hardcoded data.
 * If that endpoint's shape doesn't include a by-level breakdown in a
 * given deployment, the chart area explains that plainly instead of
 * drawing an empty or fabricated chart.
 */
function SourceHealthOverview({ sources }: { sources: any[] }) {
  const counts = useMemo(() => {
    const c = { active: 0, error: 0, pending: 0, paused: 0, disabled: 0, other: 0 }
    for (const s of sources) {
      const status = (s.status || '').toLowerCase()
      if (status in c) c[status as keyof typeof c]++
      else c.other++
    }
    return c
  }, [sources])

  const { data: stats, isLoading: statsLoading, error: statsError } = useQuery({
    queryKey: ['log-statistics', '24h'],
    queryFn: () => logsApi.getStatistics({ hours: 24 }),
    enabled: sources.length > 0,
    refetchInterval: 60000,
  })

  // Real shape from LogEventRepository.get_statistics() (backend/app/logs/repository.py):
  // a flat dict with "total" plus one count per level name - no nested
  // "by_level" key. Pull out exactly the level columns the SQL actually
  // computes; anything else in the dict (total, analyzed, with_indicators)
  // is ignored here.
  const LEVEL_KEYS = ['emergency', 'alert', 'critical', 'error', 'warning', 'info']
  const levelStats: Record<string, number> | undefined = stats?.statistics
  const chartData = levelStats
    ? LEVEL_KEYS
        .filter((level) => (levelStats[level] ?? 0) > 0)
        .map((level) => ({ level, count: levelStats[level] }))
    : null

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <div className="lg:col-span-1 grid grid-cols-2 gap-3">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <p className="text-2xl font-bold text-white">{sources.length}</p>
          <p className="text-xs text-slate-500 mt-0.5">Total Sources</p>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <p className={clsx('text-2xl font-bold', counts.active > 0 ? 'text-emerald-400' : 'text-slate-500')}>{counts.active}</p>
          <p className="text-xs text-slate-500 mt-0.5">Healthy</p>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <p className={clsx('text-2xl font-bold', counts.error > 0 ? 'text-red-400' : 'text-slate-500')}>{counts.error}</p>
          <p className="text-xs text-slate-500 mt-0.5">Failing</p>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <p className={clsx('text-2xl font-bold', counts.pending > 0 ? 'text-yellow-400' : 'text-slate-500')}>{counts.pending}</p>
          <p className="text-xs text-slate-500 mt-0.5">Pending</p>
        </div>
      </div>

      <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium text-slate-300">Events by Severity (last 24h)</h3>
        </div>
        {statsLoading ? (
          <div className="h-40 flex items-center justify-center">
            <RefreshCw className="w-5 h-5 text-slate-600 animate-spin" />
          </div>
        ) : statsError ? (
          <div className="h-40 flex items-center justify-center text-sm text-slate-500">
            Statistics are temporarily unavailable.
          </div>
        ) : !chartData ? (
          <div className="h-40 flex items-center justify-center text-sm text-slate-500 text-center px-6">
            Severity breakdown isn't available from the statistics endpoint in this deployment.
          </div>
        ) : chartData.length === 0 ? (
          <div className="h-40 flex items-center justify-center text-sm text-slate-500">
            No events in the last 24 hours.
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={chartData} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis dataKey="level" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
              <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 8, fontSize: 12 }}
                labelStyle={{ color: '#e2e8f0' }}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {chartData.map((d) => (
                  <Cell key={d.level} fill={SEVERITY_COLORS[d.level] || '#38bdf8'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  )
}

// ============================================================================
// Main Page
// ============================================================================

type TabId = 'sources' | 'events' | 'manual'
const TAB_IDS: TabId[] = ['manual', 'sources', 'events']

export function LogAnalysisPage() {
  const queryClient = useQueryClient()
  // Tab selection is synced to the ?tab= URL param so a link/bookmark/
  // browser-back can land on a specific tab. Falls back to 'manual' on a
  // missing or invalid value rather than crashing.
  const [searchParams, setSearchParams] = useSearchParams()
  const rawTab = searchParams.get('tab')
  const activeTab: TabId = TAB_IDS.includes(rawTab as TabId) ? (rawTab as TabId) : 'manual'
  const setActiveTab = (id: TabId) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      next.set('tab', id)
      return next
    })
  }
  const [showAddSource, setShowAddSource] = useState(false)
  const [nameFilter, setNameFilter] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')

  const { data: sourcesData, isLoading: sourcesLoading, error: sourcesError, refetch } = useQuery({
    // type/status are real GET /logs/sources query params (source_type,
    // status) - included in the key so switching them refetches server-side
    // rather than only filtering the already-fetched page.
    queryKey: ['log-sources', typeFilter, statusFilter],
    queryFn: () => logsApi.listSources({
      limit: 100,
      source_type: typeFilter || undefined,
      status: statusFilter || undefined,
    }),
    refetchInterval: 30000,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => logsApi.deleteSource(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['log-sources'] }),
  })

  const allSources = sourcesData?.sources || []
  // Name search has no backend equivalent (GET /logs/sources has no name/
  // search param) - filtering a page of at most 100 already-fetched
  // sources client-side is reasonable at this scale; it must not be used
  // as a substitute for the type/status filters above, which do hit the
  // server.
  const sources = nameFilter
    ? allSources.filter((s: any) => s.name?.toLowerCase().includes(nameFilter.toLowerCase()))
    : allSources

  const tabs: { id: TabId; label: string; icon: typeof Terminal }[] = [
    { id: 'manual', label: 'Manual Analysis', icon: Terminal },
    { id: 'sources', label: 'Log Sources', icon: Activity },
    { id: 'events', label: 'Log Events', icon: FileText },
  ]

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Log Analysis</h1>
          <p className="text-slate-400 mt-1">Manage log sources and analyze security events</p>
        </div>
        {activeTab === 'sources' && (
          <button
            onClick={() => setShowAddSource(true)}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" />
            Add Log Source
          </button>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-slate-800">
        {tabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={clsx(
              'flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 -mb-px transition-colors',
              activeTab === id
                ? 'text-cyan-400 border-cyan-400'
                : 'text-slate-400 border-transparent hover:text-slate-300'
            )}
          >
            <Icon className="w-4 h-4" />
            {label}
            {id === 'manual' && (
              <span
                className="flex items-center gap-1 px-1.5 py-0.5 text-xs bg-amber-500/15 text-amber-400 rounded-md"
                title="Manual analysis results are ad-hoc and are not saved to Log Events or dashboard metrics."
              >
                <FlaskConical className="w-3 h-3" />
                Ad-hoc · not saved
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Log Sources Tab */}
      {activeTab === 'sources' && (
        <div className="space-y-4">
          {allSources.length > 0 && <SourceHealthOverview sources={allSources} />}

          <div className="flex flex-wrap gap-3">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={nameFilter}
                onChange={(e) => setNameFilter(e.target.value)}
                placeholder="Search sources by name..."
                className="w-full bg-slate-800 border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 text-sm"
              />
            </div>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 text-sm"
            >
              <option value="">All Types</option>
              <option value="windows_event">Windows Event Log</option>
              <option value="linux_ssh">Linux / SSH</option>
              <option value="android_adb">Android Device</option>
            </select>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 text-sm"
            >
              <option value="">All Statuses</option>
              <option value="active">Active</option>
              <option value="pending">Pending</option>
              <option value="error">Error</option>
              <option value="paused">Paused</option>
              <option value="disabled">Disabled</option>
            </select>
          </div>

          {sourcesError ? (
            <div className="flex items-center gap-2 p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
              <XCircle className="w-5 h-5 text-red-400" />
              <p className="text-red-400 text-sm">Unable to load log sources</p>
              <button onClick={() => refetch()} className="ml-auto text-sm text-red-400 hover:text-red-300 underline">Retry</button>
            </div>
          ) : sourcesLoading ? (
            <div className="flex items-center justify-center py-12">
              <RefreshCw className="w-6 h-6 text-slate-500 animate-spin" />
            </div>
          ) : allSources.length === 0 ? (
            <div className="p-12 text-center bg-slate-900 border border-slate-800 rounded-xl border-dashed">
              <Activity className="w-12 h-12 text-slate-700 mx-auto mb-3" />
              <p className="text-slate-400 font-medium">No log sources configured</p>
              <p className="text-sm text-slate-500 mt-1 mb-6">Connect Windows, Linux, or Android log sources to start collecting events.</p>
              <button
                onClick={() => setShowAddSource(true)}
                className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors"
              >
                <Plus className="w-4 h-4" />
                Add First Log Source
              </button>
            </div>
          ) : sources.length === 0 ? (
            <div className="p-12 text-center bg-slate-900 border border-slate-800 rounded-xl border-dashed">
              <Search className="w-12 h-12 text-slate-700 mx-auto mb-3" />
              <p className="text-slate-400 font-medium">No sources match your filters</p>
              <p className="text-sm text-slate-500 mt-1">Try a different name, type, or status.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
              {sources.map((source: any) => (
                <SourceCard
                  key={source.id}
                  source={source}
                  onDelete={(id) => deleteMutation.mutate(id)}
                />
              ))}
            </div>
          )}

          {sources.length > 0 && (
            <div className="flex items-center justify-between text-sm text-slate-500 mt-2">
              <span>{sources.length} source{sources.length !== 1 ? 's' : ''} configured</span>
              <button onClick={() => refetch()} className="flex items-center gap-1 hover:text-slate-300">
                <RefreshCw className={clsx('w-3.5 h-3.5', sourcesLoading && 'animate-spin')} />
                Refresh
              </button>
            </div>
          )}
        </div>
      )}

      {/* Events Tab */}
      {activeTab === 'events' && <LogEventsTab />}

      {/* Manual Analysis Tab - intentionally mounted-but-hidden (not
          conditionally unmounted like Sources/Events above) so typed log
          text or a selected file survives switching to another tab and
          back. This is safe to keep mounted in the background: unlike
          Sources/Events, ManualAnalysisTab holds no refetchInterval
          polling query - it only runs network requests when the user
          explicitly clicks Analyze. Do not "fix" this asymmetry by making
          all three tabs consistent; Sources/Events must keep unmounting
          so their 30s poll stops the moment their tab is inactive. */}
      <div className={activeTab === 'manual' ? '' : 'hidden'}>
        <ManualAnalysisTab />
      </div>

      {/* Add Source Modal */}
      {showAddSource && <AddSourceModal onClose={() => setShowAddSource(false)} />}
    </div>
  )
}
