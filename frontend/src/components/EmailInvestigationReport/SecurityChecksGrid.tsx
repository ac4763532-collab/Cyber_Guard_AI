/**
 * Security checks grid: one tile per detector category, each honestly
 * reflecting its real backend status (never collapsing UNKNOWN into
 * FAIL, or "configured but found nothing" into a generic bucket).
 * Clicking a tile scrolls to the matching evidence panel below.
 */
import {
  User,
  ShieldCheck,
  KeyRound,
  Mail,
  Link,
  FileText,
  Paperclip,
  Server,
  Globe,
} from 'lucide-react'
import type { InvestigationReport } from './types'
import { StatusBadge } from './shared/badges'

interface Tile {
  key: string
  label: string
  icon: any
  status: string
  tooltip: string
  panelId: string
}

function buildTiles(report: InvestigationReport): Tile[] {
  const senderStatus = report.sender?.findings?.length > 0 ? 'detected' : 'not_detected'
  const spfStatus = report.authentication?.spf?.status || 'unknown'
  const dkimStatus = report.authentication?.dkim?.status || 'unknown'
  const dmarcStatus = report.authentication?.dmarc?.status || 'unknown'
  const urlStatus = report.urls?.status || (report.urls?.suspicious_urls > 0 ? 'detected' : 'not_detected')
  const contentStatus =
    report.content?.urgency_detected || report.content?.credential_request_detected ? 'detected' : 'not_detected'
  const attachmentStatus = report.attachments?.status || 'not_applicable'
  const headerStatus = report.headers?.status || 'unknown'
  const threatIntelStatus = report.threat_intel?.status || 'not_configured'

  return [
    {
      key: 'sender',
      label: 'Sender Analysis',
      icon: User,
      status: senderStatus,
      tooltip: 'Checks sender address, free-mail providers, lookalike domains, and Reply-To/Return-Path mismatches.',
      panelId: 'panel-sender',
    },
    {
      key: 'spf',
      label: 'SPF',
      icon: ShieldCheck,
      status: spfStatus,
      tooltip: 'Sender Policy Framework result. UNKNOWN means the header could not be evaluated - it is not the same as FAIL.',
      panelId: 'panel-auth',
    },
    {
      key: 'dkim',
      label: 'DKIM',
      icon: KeyRound,
      status: dkimStatus,
      tooltip: 'DomainKeys Identified Mail signature result. UNKNOWN means no verifiable result, not a failure.',
      panelId: 'panel-auth',
    },
    {
      key: 'dmarc',
      label: 'DMARC',
      icon: Mail,
      status: dmarcStatus,
      tooltip: 'Domain-based Message Authentication result. UNKNOWN means no verifiable result, not a failure.',
      panelId: 'panel-auth',
    },
    {
      key: 'url',
      label: 'URL Analysis',
      icon: Link,
      status: urlStatus,
      tooltip: 'A detected URL means a suspicious pattern was found (shortener, IP-based, lookalike) - not a confirmed malicious URL.',
      panelId: 'panel-urls',
    },
    {
      key: 'content',
      label: 'Content Analysis',
      icon: FileText,
      status: contentStatus,
      tooltip: 'Scans body text for urgency language, credential requests, and brand impersonation phrasing.',
      panelId: 'panel-content',
    },
    {
      key: 'attachment',
      label: 'Attachment Analysis',
      icon: Paperclip,
      status: attachmentStatus,
      tooltip: 'NOT APPLICABLE means this email has no attachments - that is a different outcome from scanning attachments and finding nothing.',
      panelId: 'panel-attachments',
    },
    {
      key: 'header',
      label: 'Header Forensics',
      icon: Server,
      status: headerStatus,
      tooltip: 'Checks Message-ID presence, mail-hop count, and private IPs in Received headers.',
      panelId: 'panel-headers',
    },
    {
      key: 'threat_intel',
      label: 'Threat Intelligence',
      icon: Globe,
      status: threatIntelStatus,
      tooltip: 'NOT CONFIGURED means no provider (e.g. VirusTotal) is set up - that is different from a configured lookup finding nothing (NO IOCS).',
      panelId: 'panel-threat-intel',
    },
  ]
}

function scrollToPanel(panelId: string) {
  const el = document.getElementById(panelId)
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }
}

export function SecurityChecksGrid({ report }: { report: InvestigationReport }) {
  const tiles = buildTiles(report)

  return (
    <div>
      <h3 className="text-sm font-medium text-slate-400 mb-2">Security Checks</h3>
      <div className="grid grid-cols-3 sm:grid-cols-4 lg:grid-cols-5 gap-1.5">
        {tiles.map((tile) => (
          <button
            key={tile.key}
            onClick={() => scrollToPanel(tile.panelId)}
            title={tile.tooltip}
            className="p-2 bg-slate-800 hover:bg-slate-750 rounded-lg text-left transition-colors border border-transparent hover:border-slate-600"
          >
            <div className="flex items-center gap-1.5 mb-1">
              <tile.icon className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0" />
              <span className="text-xs text-slate-400 truncate">{tile.label}</span>
            </div>
            <StatusBadge status={tile.status} />
          </button>
        ))}
      </div>
    </div>
  )
}
