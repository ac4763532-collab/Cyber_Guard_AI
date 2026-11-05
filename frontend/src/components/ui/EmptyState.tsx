/**
 * Empty State Components
 *
 * Guide users when no data is available.
 */

import { clsx } from 'clsx'
import { Link } from 'react-router-dom'
import {
  Inbox,
  Search,
  FileQuestion,
  AlertCircle,
  Plus,
  ArrowRight,
  Mail,
  FileText,
  Network,
} from 'lucide-react'

interface EmptyStateProps {
  icon?: React.ComponentType<{ className?: string }>
  title: string
  description: string
  action?: {
    label: string
    onClick?: () => void
    href?: string
  }
  secondaryAction?: {
    label: string
    onClick?: () => void
    href?: string
  }
  className?: string
}

export function EmptyState({
  icon: Icon = Inbox,
  title,
  description,
  action,
  secondaryAction,
  className,
}: EmptyStateProps) {
  return (
    <div className={clsx('text-center py-12 px-4', className)}>
      <div className="inline-flex items-center justify-center w-16 h-16 bg-slate-800 rounded-full mb-4">
        <Icon className="w-8 h-8 text-slate-500" />
      </div>
      <h3 className="text-lg font-medium text-white mb-2">{title}</h3>
      <p className="text-slate-400 max-w-sm mx-auto mb-6">{description}</p>

      {(action || secondaryAction) && (
        <div className="flex items-center justify-center gap-3">
          {action && (
            action.href ? (
              <Link
                to={action.href}
                className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors"
              >
                <Plus className="w-4 h-4" />
                {action.label}
              </Link>
            ) : (
              <button
                onClick={action.onClick}
                className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors"
              >
                <Plus className="w-4 h-4" />
                {action.label}
              </button>
            )
          )}
          {secondaryAction && (
            secondaryAction.href ? (
              <Link
                to={secondaryAction.href}
                className="inline-flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors"
              >
                {secondaryAction.label}
                <ArrowRight className="w-4 h-4" />
              </Link>
            ) : (
              <button
                onClick={secondaryAction.onClick}
                className="inline-flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors"
              >
                {secondaryAction.label}
                <ArrowRight className="w-4 h-4" />
              </button>
            )
          )}
        </div>
      )}
    </div>
  )
}

export function NoSearchResults({ query }: { query: string }) {
  return (
    <EmptyState
      icon={Search}
      title="No results found"
      description={`No matches for "${query}". Try adjusting your search terms.`}
    />
  )
}

export function NoDataYet({ type }: { type: 'alerts' | 'events' | 'reports' }) {
  const config = {
    alerts: {
      icon: AlertCircle,
      title: 'No alerts yet',
      description: 'When security alerts are triggered, they will appear here.',
    },
    events: {
      icon: FileText,
      title: 'No events recorded',
      description: 'Security events from your monitored systems will show up here.',
    },
    reports: {
      icon: FileQuestion,
      title: 'No reports generated',
      description: 'Generate a security report to see it here.',
    },
  }

  const { icon, title, description } = config[type]

  return <EmptyState icon={icon} title={title} description={description} />
}

export function GetStartedCard() {
  const actions = [
    {
      icon: Mail,
      title: 'Analyze an Email',
      description: 'Check emails for phishing and threats',
      href: '/analysis/email',
      color: 'text-cyan-400',
      bg: 'bg-cyan-500/20',
    },
    {
      icon: FileText,
      title: 'Analyze Logs',
      description: 'Detect security anomalies in logs',
      href: '/analysis/logs',
      color: 'text-purple-400',
      bg: 'bg-purple-500/20',
    },
    {
      icon: Network,
      title: 'Scan Network',
      description: 'Find vulnerabilities in your network',
      href: '/analysis/network',
      color: 'text-orange-400',
      bg: 'bg-orange-500/20',
    },
  ]

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
      <h3 className="text-lg font-semibold text-white mb-2">Get Started</h3>
      <p className="text-slate-400 text-sm mb-6">
        Start analyzing threats with these quick actions
      </p>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {actions.map((action) => (
          <Link
            key={action.href}
            to={action.href}
            className="group p-4 bg-slate-800/50 hover:bg-slate-800 border border-slate-700 rounded-lg transition-colors"
          >
            <div className={clsx('inline-flex p-2 rounded-lg mb-3', action.bg)}>
              <action.icon className={clsx('w-5 h-5', action.color)} />
            </div>
            <h4 className="text-white font-medium group-hover:text-cyan-400 transition-colors">
              {action.title}
            </h4>
            <p className="text-sm text-slate-500 mt-1">{action.description}</p>
          </Link>
        ))}
      </div>
    </div>
  )
}
