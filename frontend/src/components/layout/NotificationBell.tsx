/**
 * CyberGuard AI - Notification Bell
 *
 * Real in-app notification inbox, fed by the authenticated user's own
 * notifications (GET /notifications, /notifications/unread-count,
 * POST /notifications/{id}/read) - these are the real delivery records
 * created by CorrelationAlertIntegration when an alert/incident is
 * created, not a client-side guess at "open alerts".
 */

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Bell, Check } from 'lucide-react'
import { clsx } from 'clsx'
import { notificationsApi } from '@/services/api'
import { SeverityBadge } from '@/components/ui'
import type { NotificationItem } from '@/types'

function timeAgo(iso: string): string {
  const diffMs = Date.now() - new Date(iso).getTime()
  const minutes = Math.floor(diffMs / 60000)
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

export function NotificationBell() {
  const [open, setOpen] = useState(false)
  const queryClient = useQueryClient()

  const { data: unread } = useQuery({
    queryKey: ['notifications', 'unread-count'],
    queryFn: notificationsApi.getUnreadCount,
    refetchInterval: 30000,
  })

  const { data: notifications, isLoading } = useQuery({
    queryKey: ['notifications', 'list'],
    queryFn: () => notificationsApi.list({ limit: 20 }),
    enabled: open, // only fetch the list once the dropdown is actually opened
    refetchInterval: open ? 30000 : false,
  })

  const markRead = useMutation({
    mutationFn: (id: string) => notificationsApi.markRead(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notifications'] })
    },
  })

  const unreadCount = unread?.unread_count || 0
  const items: NotificationItem[] = notifications || []

  return (
    <div className="relative">
      <button
        onClick={() => setOpen(!open)}
        className="relative p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
        aria-label={`Notifications${unreadCount > 0 ? `, ${unreadCount} unread` : ''}`}
        aria-expanded={open}
        aria-haspopup="true"
      >
        <Bell className="w-5 h-5" />
        {unreadCount > 0 && (
          <span className="absolute -top-1 -right-1 min-w-[18px] h-[18px] flex items-center justify-center px-1 text-xs font-medium bg-red-500 text-white rounded-full">
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <div className="absolute right-0 top-full mt-2 w-96 bg-slate-800 border border-slate-700 rounded-xl shadow-xl z-20 overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
              <h3 className="text-sm font-semibold text-white">Notifications</h3>
              {unreadCount > 0 && (
                <span className="text-xs text-slate-400">{unreadCount} unread</span>
              )}
            </div>

            <div className="max-h-96 overflow-y-auto">
              {isLoading ? (
                <div className="p-4 text-sm text-slate-500 text-center">Loading...</div>
              ) : items.length === 0 ? (
                <div className="p-6 text-center">
                  <Bell className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                  <p className="text-sm text-slate-400">No notifications yet</p>
                  <p className="text-xs text-slate-500 mt-1">
                    You'll see alerts and incidents here as they happen.
                  </p>
                </div>
              ) : (
                items.map((n) => (
                  <button
                    key={n.id}
                    onClick={() => {
                      if (n.status !== 'read') markRead.mutate(n.id)
                    }}
                    className={clsx(
                      'w-full text-left px-4 py-3 border-b border-slate-700/50 hover:bg-slate-700/50 transition-colors',
                      n.status !== 'read' && 'bg-slate-700/20'
                    )}
                  >
                    <div className="flex items-start gap-2">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <SeverityBadge severity={n.severity} />
                          {n.status !== 'read' && (
                            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                          )}
                        </div>
                        <p className="text-sm font-medium text-white truncate">{n.title}</p>
                        <p className="text-xs text-slate-400 mt-0.5 line-clamp-2">{n.summary}</p>
                        <p className="text-xs text-slate-500 mt-1">{timeAgo(n.created_at)}</p>
                      </div>
                      {n.status === 'read' && (
                        <Check className="w-4 h-4 text-slate-600 flex-shrink-0 mt-1" />
                      )}
                    </div>
                  </button>
                ))
              )}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
