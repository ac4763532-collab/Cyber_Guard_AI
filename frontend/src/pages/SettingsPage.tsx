/**
 * CyberGuard AI - Settings Page
 *
 * User settings and system configuration.
 */

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  User,
  Shield,
  Database,
  CheckCircle2,
  AlertTriangle,
  Bell,
} from 'lucide-react'
import { clsx } from 'clsx'
import { authApi, healthApi, detectionApi } from '@/services/api'
import { NotificationSettings } from '@/components/settings/NotificationSettings'

export function SettingsPage() {
  const [activeTab, setActiveTab] = useState<'profile' | 'system' | 'detection' | 'notifications'>('profile')

  // Get current user
  const user = authApi.getUser()

  // Fetch system health
  const { data: health } = useQuery({
    queryKey: ['health', 'detailed'],
    queryFn: healthApi.detailed,
  })

  // Fetch detection stats
  const { data: detectionStats } = useQuery({
    queryKey: ['detection', 'statistics'],
    queryFn: detectionApi.getStatistics,
    enabled: activeTab === 'detection',
  })

  // Fetch rules
  const { data: rules } = useQuery({
    queryKey: ['detection', 'rules'],
    queryFn: detectionApi.getRules,
    enabled: activeTab === 'detection',
  })

  // Fetch IOCs
  const { data: iocs } = useQuery({
    queryKey: ['detection', 'iocs'],
    queryFn: detectionApi.getIOCs,
    enabled: activeTab === 'detection',
  })

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Settings</h1>
        <p className="text-slate-400 mt-1">Manage your account and system settings</p>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-slate-800">
        {[
          { id: 'profile', label: 'Profile', icon: User },
          { id: 'system', label: 'System', icon: Database },
          { id: 'detection', label: 'Detection', icon: Shield },
          { id: 'notifications', label: 'Notifications', icon: Bell },
        ].map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id as any)}
            className={clsx(
              'flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 -mb-px transition-colors',
              activeTab === id
                ? 'text-cyan-400 border-cyan-400'
                : 'text-slate-400 border-transparent hover:text-slate-300'
            )}
          >
            <Icon className="w-4 h-4" />
            {label}
          </button>
        ))}
      </div>

      {/* Profile Tab */}
      {activeTab === 'profile' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl">
            <div className="px-6 py-4 border-b border-slate-800">
              <h2 className="text-lg font-semibold text-white">User Profile</h2>
            </div>
            <div className="p-6">
              {user ? (
                <div className="space-y-4">
                  <div className="flex items-center gap-4">
                    <div className="w-16 h-16 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-full flex items-center justify-center">
                      <span className="text-2xl font-bold text-white">
                        {user.username?.charAt(0).toUpperCase()}
                      </span>
                    </div>
                    <div>
                      <p className="text-xl font-semibold text-white">{user.full_name || user.username}</p>
                      <p className="text-slate-400">{user.username}</p>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4 mt-6">
                    <div className="bg-slate-800/50 rounded-lg p-4">
                      <p className="text-sm text-slate-500">Role</p>
                      <p className="text-white font-medium capitalize">{user.role}</p>
                    </div>
                    <div className="bg-slate-800/50 rounded-lg p-4">
                      <p className="text-sm text-slate-500">User ID</p>
                      <p className="text-white font-mono text-sm">{user.id?.slice(0, 8)}</p>
                    </div>
                  </div>

                  <div className="pt-4 border-t border-slate-800">
                    <h3 className="text-sm font-medium text-slate-300 mb-3">Permissions</h3>
                    <div className="grid grid-cols-2 gap-2">
                      {[
                        { key: 'can_create_alerts', label: 'Create Alerts' },
                        { key: 'can_manage_incidents', label: 'Manage Incidents' },
                        { key: 'can_run_analysis', label: 'Run Analysis' },
                        { key: 'can_manage_users', label: 'Manage Users' },
                      ].map(({ key, label }) => (
                        <div key={key} className="flex items-center gap-2">
                          {user[key] ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                          ) : (
                            <AlertTriangle className="w-4 h-4 text-slate-500" />
                          )}
                          <span className={user[key] ? 'text-slate-300' : 'text-slate-500'}>
                            {label}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <p className="text-slate-500">Not logged in</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* System Tab */}
      {activeTab === 'system' && (
        <div className="space-y-6">
          {/* System Info */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl">
            <div className="px-6 py-4 border-b border-slate-800">
              <h2 className="text-lg font-semibold text-white">System Information</h2>
            </div>
            <div className="p-6">
              {health && (
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="bg-slate-800/50 rounded-lg p-4">
                    <p className="text-sm text-slate-500">Version</p>
                    <p className="text-white font-medium">{health.version}</p>
                  </div>
                  <div className="bg-slate-800/50 rounded-lg p-4">
                    <p className="text-sm text-slate-500">Environment</p>
                    <p className="text-white font-medium capitalize">{health.environment}</p>
                  </div>
                  <div className="bg-slate-800/50 rounded-lg p-4">
                    <p className="text-sm text-slate-500">Status</p>
                    <p className={clsx(
                      'font-medium capitalize',
                      health.status === 'healthy' ? 'text-emerald-400' :
                      health.status === 'degraded' ? 'text-yellow-400' : 'text-red-400'
                    )}>
                      {health.status}
                    </p>
                  </div>
                  <div className="bg-slate-800/50 rounded-lg p-4">
                    <p className="text-sm text-slate-500">Components</p>
                    <p className="text-white font-medium">
                      {health.components ? Object.keys(health.components).length : 0} active
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>

        </div>
      )}

      {/* Detection Tab */}
      {activeTab === 'detection' && (
        <div className="space-y-6">
          {/* Detection Stats */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl">
            <div className="px-6 py-4 border-b border-slate-800">
              <h2 className="text-lg font-semibold text-white">Detection Engine</h2>
            </div>
            <div className="p-6">
              {detectionStats && (
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="bg-slate-800/50 rounded-lg p-4">
                    <p className="text-sm text-slate-500">Detection Rules</p>
                    <p className="text-2xl font-bold text-white">{detectionStats.rules?.total_rules || 0}</p>
                  </div>
                  <div className="bg-slate-800/50 rounded-lg p-4">
                    <p className="text-sm text-slate-500">Active Rules</p>
                    <p className="text-2xl font-bold text-emerald-400">{detectionStats.rules?.enabled || 0}</p>
                  </div>
                  <div className="bg-slate-800/50 rounded-lg p-4">
                    <p className="text-sm text-slate-500">IOC Database</p>
                    <p className="text-2xl font-bold text-cyan-400">{detectionStats.iocs?.total || 0}</p>
                  </div>
                  <div className="bg-slate-800/50 rounded-lg p-4">
                    <p className="text-sm text-slate-500">Anomaly Detection</p>
                    <p className="text-2xl font-bold text-purple-400">
                      {detectionStats.anomaly?.enabled ? 'Active' : 'Inactive'}
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Rules List */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl">
            <div className="px-6 py-4 border-b border-slate-800">
              <h2 className="text-lg font-semibold text-white">Detection Rules</h2>
            </div>
            <div className="divide-y divide-slate-800">
              {rules?.rules && rules.rules.length > 0 ? (
                rules.rules.map((rule: any) => (
                  <div key={rule.rule_id} className="px-6 py-4 flex items-center justify-between">
                    <div>
                      <p className="text-white font-medium">{rule.rule_name}</p>
                      <p className="text-sm text-slate-500">{rule.description}</p>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className={clsx(
                        'px-2 py-0.5 text-xs rounded',
                        rule.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                        rule.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                        rule.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-blue-500/20 text-blue-400'
                      )}>
                        {rule.severity}
                      </span>
                      <span className={clsx(
                        'px-2 py-0.5 text-xs rounded',
                        rule.enabled ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-500/20 text-slate-400'
                      )}>
                        {rule.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="px-6 py-8 text-center text-slate-500">
                  No detection rules loaded
                </div>
              )}
            </div>
          </div>

          {/* IOC Summary */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl">
            <div className="px-6 py-4 border-b border-slate-800">
              <h2 className="text-lg font-semibold text-white">IOC Database</h2>
            </div>
            <div className="p-6">
              {iocs?.by_type && Object.keys(iocs.by_type).length > 0 ? (
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  {Object.entries(iocs.by_type).map(([type, count]) => (
                    <div key={type} className="bg-slate-800/50 rounded-lg p-4">
                      <p className="text-sm text-slate-500 capitalize">{type}</p>
                      <p className="text-xl font-bold text-white">{count as number}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-slate-500">No IOC data</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Notifications Tab */}
      {activeTab === 'notifications' && <NotificationSettings />}
    </div>
  )
}
