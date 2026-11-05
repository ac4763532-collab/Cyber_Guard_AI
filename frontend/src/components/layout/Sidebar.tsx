/**
 * CyberGuard AI - Sidebar Navigation
 */

import { Link, useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  Shield,
  LayoutDashboard,
  Mail,
  FileText,
  Network,
  Activity,
  Bell,
  Cpu,
  FileBarChart,
  Settings,
  ChevronLeft,
  ChevronRight,
  GitMerge,
  MessageSquareWarning,
  Fingerprint,
  ShieldAlert,
} from 'lucide-react'
import { clsx } from 'clsx'
import { useState } from 'react'
import { alertsApi, healthApi } from '@/services/api'
import { useAuth } from '@/contexts/AuthContext'

interface NavItem {
  name: string
  href: string
  icon: React.ComponentType<{ className?: string }>
  badge?: number
  badgeColor?: string
}

const mainNavItems: NavItem[] = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Email Analysis', href: '/analysis/email', icon: Mail },
  { name: 'Log Analysis', href: '/analysis/logs', icon: FileText },
  { name: 'Network Analysis', href: '/analysis/network', icon: Network },
]

const intelligenceNavItems: NavItem[] = [
  { name: 'Correlation', href: '/correlation', icon: GitMerge },
  { name: 'Threat Intel', href: '/threat-intel', icon: Fingerprint },
  { name: 'Incidents', href: '/incidents', icon: ShieldAlert },
]

const systemNavItems: NavItem[] = [
  { name: 'Agents', href: '/agents', icon: Cpu },
  { name: 'Reports', href: '/reports', icon: FileBarChart },
  { name: 'Settings', href: '/settings', icon: Settings },
]

function NavSection({ title, items, collapsed }: { title: string; items: NavItem[]; collapsed: boolean }) {
  const location = useLocation()

  return (
    <div className="mb-6">
      {!collapsed && (
        <h3 className="px-4 mb-2 text-xs font-semibold text-slate-500 uppercase tracking-wider">
          {title}
        </h3>
      )}
      <nav className="space-y-1">
        {items.map((item) => {
          const isActive = location.pathname === item.href
          return (
            <Link
              key={item.name}
              to={item.href}
              className={clsx(
                'flex items-center gap-3 px-4 py-2.5 text-sm font-medium rounded-lg mx-2 transition-colors',
                isActive
                  ? 'bg-gradient-to-r from-cyan-500/20 to-teal-500/20 text-cyan-400 border-l-2 border-cyan-400'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              )}
              title={collapsed ? item.name : undefined}
            >
              <item.icon className={clsx('w-5 h-5 flex-shrink-0', isActive && 'text-cyan-400')} />
              {!collapsed && (
                <>
                  <span className="flex-1">{item.name}</span>
                  {item.badge !== undefined && item.badge > 0 && (
                    <span className={clsx('px-2 py-0.5 text-xs font-medium rounded-full text-white', item.badgeColor)}>
                      {item.badge}
                    </span>
                  )}
                </>
              )}
              {collapsed && item.badge !== undefined && item.badge > 0 && (
                <span className={clsx('absolute right-2 w-2 h-2 rounded-full', item.badgeColor)} />
              )}
            </Link>
          )
        })}
      </nav>
    </div>
  )
}

export function Sidebar() {
  const [collapsed, setCollapsed] = useState(false)
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'

  // Fetch real-time badge counts
  const { data: alertStats } = useQuery({
    queryKey: ['alerts', 'statistics'],
    queryFn: alertsApi.getStatistics,
    refetchInterval: 30000,
  })

  const { data: health } = useQuery({
    queryKey: ['health', 'detailed'],
    queryFn: healthApi.detailed,
    refetchInterval: 60000,
  })

  // Dynamic monitoring nav items with real counts
  const monitoringNavItems: NavItem[] = [
    { name: 'Events', href: '/events', icon: Activity },
    {
      name: 'Alerts',
      href: '/alerts',
      icon: Bell,
      badge: alertStats?.open || 0,
      badgeColor: 'bg-yellow-500'
    },
  ]

  // Feedback is useful to every authenticated user (submit); the review
  // queue inside the page itself is further gated to admins. Training is
  // admin-only end to end, so only show the nav entry for admins.
  const systemItemsWithRoleGating: NavItem[] = [
    ...systemNavItems,
    { name: 'Feedback', href: '/feedback', icon: MessageSquareWarning },
    ...(isAdmin ? [{ name: 'Training', href: '/training', icon: Cpu }] : []),
  ]

  // Determine system status
  const systemStatus = health?.status || 'unknown'
  const statusColor = {
    healthy: 'bg-emerald-500',
    degraded: 'bg-yellow-500',
    unhealthy: 'bg-red-500',
    unknown: 'bg-slate-500',
  }[systemStatus] || 'bg-slate-500'

  const statusText = {
    healthy: 'System Online',
    degraded: 'System Degraded',
    unhealthy: 'System Unhealthy',
    unknown: 'Connecting...',
  }[systemStatus] || 'Unknown'

  return (
    <aside className={clsx(
      'h-screen bg-slate-900 border-r border-slate-800 flex flex-col transition-all duration-300',
      collapsed ? 'w-20' : 'w-64'
    )}>
      {/* Logo */}
      <div className="h-16 flex items-center justify-between px-4 border-b border-slate-800">
        <Link to="/" className="flex items-center gap-3">
          <div className="w-10 h-10 bg-gradient-to-br from-cyan-500 to-teal-500 rounded-xl flex items-center justify-center">
            <Shield className="w-6 h-6 text-white" />
          </div>
          {!collapsed && (
            <div>
              <h1 className="text-lg font-bold text-white">CyberGuard</h1>
              <p className="text-xs text-cyan-400">AI Security Platform</p>
            </div>
          )}
        </Link>
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="p-1.5 text-slate-500 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
        >
          {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </div>

      {/* Navigation */}
      <div className="flex-1 py-6 overflow-y-auto">
        <NavSection title="Analysis" items={mainNavItems} collapsed={collapsed} />
        <NavSection title="Monitoring" items={monitoringNavItems} collapsed={collapsed} />
        <NavSection title="Intelligence" items={intelligenceNavItems} collapsed={collapsed} />
        <NavSection title="System" items={systemItemsWithRoleGating} collapsed={collapsed} />
      </div>

      {/* Status indicator */}
      <div className="p-4 border-t border-slate-800">
        <div className={clsx(
          'flex items-center gap-3 px-3 py-2 bg-slate-800 rounded-lg',
          collapsed && 'justify-center'
        )}>
          <div className={clsx('w-2 h-2 rounded-full', statusColor, systemStatus === 'healthy' && 'status-online')} />
          {!collapsed && (
            <span className="text-xs text-slate-400">{statusText}</span>
          )}
        </div>
      </div>
    </aside>
  )
}
