/**
 * Keyboard Shortcuts System
 *
 * Global keyboard shortcuts for power users.
 */

import { useEffect, useState, createContext, useContext } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Keyboard,
  X,
  LayoutDashboard,
  Mail,
  FileText,
  Network,
  Bell,
  Settings,
  Search,
  Command,
} from 'lucide-react'

interface ShortcutsContextType {
  showHelp: () => void
  hideHelp: () => void
}

const ShortcutsContext = createContext<ShortcutsContextType | null>(null)

export function useShortcuts() {
  return useContext(ShortcutsContext)
}

const shortcuts = [
  { key: 'g d', label: 'Go to Dashboard', icon: LayoutDashboard, path: '/' },
  { key: 'g e', label: 'Go to Email Analysis', icon: Mail, path: '/analysis/email' },
  { key: 'g l', label: 'Go to Log Analysis', icon: FileText, path: '/analysis/logs' },
  { key: 'g n', label: 'Go to Network Analysis', icon: Network, path: '/analysis/network' },
  { key: 'g a', label: 'Go to Alerts', icon: Bell, path: '/alerts' },
  { key: 'g s', label: 'Go to Settings', icon: Settings, path: '/settings' },
  { key: '/', label: 'Focus Search', icon: Search },
  { key: '?', label: 'Show Shortcuts', icon: Keyboard },
  { key: 'Esc', label: 'Close Modal / Cancel', icon: X },
]

function ShortcutsModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-lg mx-4 overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-500/20 rounded-lg">
              <Keyboard className="w-5 h-5 text-cyan-400" />
            </div>
            <h2 className="text-lg font-semibold text-white">Keyboard Shortcuts</h2>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Shortcuts List */}
        <div className="p-6 space-y-3 max-h-96 overflow-y-auto">
          <div className="mb-4">
            <h3 className="text-sm font-medium text-slate-400 mb-2">Navigation</h3>
            <p className="text-xs text-slate-500">Press keys in sequence (e.g., g then d)</p>
          </div>

          {shortcuts.map((shortcut) => (
            <div
              key={shortcut.key}
              className="flex items-center justify-between py-2 px-3 bg-slate-800/50 rounded-lg"
            >
              <div className="flex items-center gap-3">
                <shortcut.icon className="w-4 h-4 text-slate-500" />
                <span className="text-sm text-slate-300">{shortcut.label}</span>
              </div>
              <div className="flex items-center gap-1">
                {shortcut.key.split(' ').map((k, i) => (
                  <span key={i} className="flex items-center gap-1">
                    {i > 0 && <span className="text-slate-600 text-xs">then</span>}
                    <kbd className="px-2 py-1 bg-slate-700 border border-slate-600 rounded text-xs font-mono text-slate-300">
                      {k === '/' ? '/' : k === '?' ? '?' : k}
                    </kbd>
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 bg-slate-800/50 border-t border-slate-800">
          <p className="text-xs text-slate-500 text-center">
            Press <kbd className="px-1.5 py-0.5 bg-slate-700 rounded text-slate-400">?</kbd> anytime to show this help
          </p>
        </div>
      </div>
    </div>
  )
}

export function KeyboardShortcutsProvider({ children }: { children: React.ReactNode }) {
  const [showModal, setShowModal] = useState(false)
  const [keySequence, setKeySequence] = useState<string[]>([])
  const navigate = useNavigate()

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ignore if typing in input/textarea
      const target = e.target as HTMLElement
      if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable) {
        if (e.key === 'Escape') {
          target.blur()
        }
        return
      }

      // Handle Escape
      if (e.key === 'Escape') {
        setShowModal(false)
        setKeySequence([])
        return
      }

      // Handle ? for help
      if (e.key === '?' || (e.shiftKey && e.key === '/')) {
        e.preventDefault()
        setShowModal(true)
        return
      }

      // Handle / for search focus
      if (e.key === '/' && !e.shiftKey) {
        e.preventDefault()
        const searchInput = document.querySelector('[data-search-input]') as HTMLInputElement
        if (searchInput) {
          searchInput.focus()
        }
        return
      }

      // Handle key sequences (g + key)
      const key = e.key.toLowerCase()

      if (keySequence.length === 0 && key === 'g') {
        setKeySequence(['g'])
        // Clear sequence after timeout
        setTimeout(() => setKeySequence([]), 1000)
        return
      }

      if (keySequence[0] === 'g') {
        const shortcut = shortcuts.find(s => s.key === `g ${key}`)
        if (shortcut && shortcut.path) {
          e.preventDefault()
          navigate(shortcut.path)
        }
        setKeySequence([])
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [keySequence, navigate])

  return (
    <ShortcutsContext.Provider value={{ showHelp: () => setShowModal(true), hideHelp: () => setShowModal(false) }}>
      {children}
      <ShortcutsModal isOpen={showModal} onClose={() => setShowModal(false)} />

      {/* Key sequence indicator */}
      {keySequence.length > 0 && (
        <div className="fixed bottom-4 left-4 z-50 px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg shadow-lg">
          <div className="flex items-center gap-2">
            <Command className="w-4 h-4 text-cyan-400" />
            <span className="text-sm text-slate-300">
              {keySequence.join(' ')} + ...
            </span>
          </div>
        </div>
      )}
    </ShortcutsContext.Provider>
  )
}
