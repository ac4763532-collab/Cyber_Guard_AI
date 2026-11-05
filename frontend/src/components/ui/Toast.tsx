/**
 * Toast Notification System
 *
 * Provides user feedback for actions with animated toast notifications.
 */

import { useState, useEffect, createContext, useContext, useCallback } from 'react'
import { CheckCircle2, XCircle, AlertTriangle, Info, X } from 'lucide-react'
import { clsx } from 'clsx'

type ToastType = 'success' | 'error' | 'warning' | 'info'

interface Toast {
  id: string
  type: ToastType
  title: string
  message?: string
  duration?: number
}

interface ToastContextType {
  toasts: Toast[]
  addToast: (toast: Omit<Toast, 'id'>) => void
  removeToast: (id: string) => void
  success: (title: string, message?: string) => void
  error: (title: string, message?: string) => void
  warning: (title: string, message?: string) => void
  info: (title: string, message?: string) => void
}

const ToastContext = createContext<ToastContextType | null>(null)

export function useToast() {
  const context = useContext(ToastContext)
  if (!context) {
    throw new Error('useToast must be used within ToastProvider')
  }
  return context
}

const toastConfig = {
  success: {
    icon: CheckCircle2,
    bg: 'bg-emerald-500/10 border-emerald-500/30',
    iconColor: 'text-emerald-400',
    titleColor: 'text-emerald-400',
  },
  error: {
    icon: XCircle,
    bg: 'bg-red-500/10 border-red-500/30',
    iconColor: 'text-red-400',
    titleColor: 'text-red-400',
  },
  warning: {
    icon: AlertTriangle,
    bg: 'bg-yellow-500/10 border-yellow-500/30',
    iconColor: 'text-yellow-400',
    titleColor: 'text-yellow-400',
  },
  info: {
    icon: Info,
    bg: 'bg-cyan-500/10 border-cyan-500/30',
    iconColor: 'text-cyan-400',
    titleColor: 'text-cyan-400',
  },
}

function ToastItem({ toast, onRemove }: { toast: Toast; onRemove: () => void }) {
  const [isExiting, setIsExiting] = useState(false)
  const config = toastConfig[toast.type]
  const Icon = config.icon

  useEffect(() => {
    const duration = toast.duration || 5000
    const exitTimer = setTimeout(() => setIsExiting(true), duration - 300)
    const removeTimer = setTimeout(onRemove, duration)

    return () => {
      clearTimeout(exitTimer)
      clearTimeout(removeTimer)
    }
  }, [toast.duration, onRemove])

  const handleClose = () => {
    setIsExiting(true)
    setTimeout(onRemove, 300)
  }

  return (
    <div
      className={clsx(
        'flex items-start gap-3 p-4 rounded-lg border backdrop-blur-sm shadow-lg transition-all duration-300',
        config.bg,
        isExiting ? 'opacity-0 translate-x-4' : 'opacity-100 translate-x-0'
      )}
    >
      <Icon className={clsx('w-5 h-5 flex-shrink-0 mt-0.5', config.iconColor)} />
      <div className="flex-1 min-w-0">
        <p className={clsx('font-medium text-sm', config.titleColor)}>{toast.title}</p>
        {toast.message && (
          <p className="text-sm text-slate-400 mt-0.5">{toast.message}</p>
        )}
      </div>
      <button
        onClick={handleClose}
        className="text-slate-500 hover:text-slate-300 transition-colors"
      >
        <X className="w-4 h-4" />
      </button>
    </div>
  )
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])

  const addToast = useCallback((toast: Omit<Toast, 'id'>) => {
    const id = Math.random().toString(36).substring(2, 9)
    setToasts((prev) => [...prev, { ...toast, id }])
  }, [])

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  const success = useCallback((title: string, message?: string) => {
    addToast({ type: 'success', title, message })
  }, [addToast])

  const error = useCallback((title: string, message?: string) => {
    addToast({ type: 'error', title, message })
  }, [addToast])

  const warning = useCallback((title: string, message?: string) => {
    addToast({ type: 'warning', title, message })
  }, [addToast])

  const info = useCallback((title: string, message?: string) => {
    addToast({ type: 'info', title, message })
  }, [addToast])

  return (
    <ToastContext.Provider value={{ toasts, addToast, removeToast, success, error, warning, info }}>
      {children}

      {/* Toast Container */}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 w-80">
        {toasts.map((toast) => (
          <ToastItem
            key={toast.id}
            toast={toast}
            onRemove={() => removeToast(toast.id)}
          />
        ))}
      </div>
    </ToastContext.Provider>
  )
}
