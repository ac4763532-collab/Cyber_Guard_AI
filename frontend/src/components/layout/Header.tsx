/**
 * CyberGuard AI - Header Component
 *
 * Top navigation with search, notifications, and user menu.
 */

import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Search,
  LogOut,
  Settings,
  Shield,
  ChevronDown,
  Keyboard,
} from 'lucide-react'
import { clsx } from 'clsx'
import { useAuth } from '@/contexts/AuthContext'
import { useShortcuts } from '@/components/ui'
import { NotificationBell } from './NotificationBell'

export function Header() {
  const navigate = useNavigate()
  const { user, logout, isFirebaseEnabled } = useAuth()
  const [showUserMenu, setShowUserMenu] = useState(false)
  const shortcuts = useShortcuts()

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  // Get user display info
  const displayName = user?.displayName || user?.email?.split('@')[0] || 'User'
  const displayEmail = user?.email || 'No email'
  const userInitial = displayName.charAt(0).toUpperCase()
  const userRole = user?.role || (user?.provider === 'demo' ? 'Demo' : 'User')

  // Determine provider badge
  const providerBadge = () => {
    if (!user) return null
    switch (user.provider) {
      case 'google':
        return (
          <span className="px-1.5 py-0.5 text-[10px] font-medium bg-blue-500/20 text-blue-400 rounded">
            Google
          </span>
        )
      case 'phone':
        return (
          <span className="px-1.5 py-0.5 text-[10px] font-medium bg-green-500/20 text-green-400 rounded">
            Phone
          </span>
        )
      case 'demo':
        return (
          <span className="px-1.5 py-0.5 text-[10px] font-medium bg-amber-500/20 text-amber-400 rounded">
            Demo
          </span>
        )
      default:
        return null
    }
  }

  return (
    <header className="h-16 bg-slate-900 border-b border-slate-800 flex items-center justify-between px-6">
      {/* Left side - Search */}
      <div className="flex-1 max-w-xl">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            data-search-input
            placeholder="Search events, incidents, IOCs... (Press /)"
            className="w-full bg-slate-800 border border-slate-700 rounded-lg py-2 pl-10 pr-4 text-sm text-slate-300 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
          />
        </div>
      </div>

      {/* Right side - Actions */}
      <div className="flex items-center gap-2">
        {/* Keyboard shortcuts help */}
        <button
          onClick={() => shortcuts?.showHelp()}
          className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors hidden sm:flex"
          aria-label="Keyboard shortcuts"
          title="Keyboard shortcuts (?)"
        >
          <Keyboard className="w-5 h-5" />
        </button>

        {/* Notifications */}
        <NotificationBell />

        {/* User menu */}
        <div className="relative">
          <button
            onClick={() => setShowUserMenu(!showUserMenu)}
            className="flex items-center gap-3 pl-4 border-l border-slate-700 hover:bg-slate-800/50 rounded-r-lg pr-2 py-1 transition-colors"
            aria-expanded={showUserMenu}
            aria-haspopup="true"
          >
            <div className="text-right hidden sm:block">
              <p className="text-sm font-medium text-white">{displayName}</p>
              <p className="text-xs text-slate-500 capitalize">{userRole}</p>
            </div>

            {/* Avatar */}
            {user?.photoURL ? (
              <img
                src={user.photoURL}
                alt={displayName}
                className="w-9 h-9 rounded-full object-cover border-2 border-slate-700"
              />
            ) : (
              <div className="w-9 h-9 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-full flex items-center justify-center">
                <span className="text-sm font-bold text-white">{userInitial}</span>
              </div>
            )}

            <ChevronDown
              className={clsx(
                'w-4 h-4 text-slate-500 transition-transform hidden sm:block',
                showUserMenu && 'rotate-180'
              )}
            />
          </button>

          {/* Dropdown menu */}
          {showUserMenu && (
            <>
              <div
                className="fixed inset-0 z-10"
                onClick={() => setShowUserMenu(false)}
              />
              <div className="absolute right-0 top-full mt-2 w-64 bg-slate-800 border border-slate-700 rounded-xl shadow-xl z-20 overflow-hidden">
                {/* User info */}
                <div className="p-4 bg-slate-800/50">
                  <div className="flex items-center gap-3">
                    {user?.photoURL ? (
                      <img
                        src={user.photoURL}
                        alt={displayName}
                        className="w-10 h-10 rounded-full object-cover"
                      />
                    ) : (
                      <div className="w-10 h-10 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-full flex items-center justify-center">
                        <span className="text-sm font-bold text-white">{userInitial}</span>
                      </div>
                    )}
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-white truncate">{displayName}</p>
                      <p className="text-xs text-slate-400 truncate">{displayEmail}</p>
                    </div>
                  </div>

                  {/* Provider badge and verification status */}
                  <div className="flex items-center gap-2 mt-3">
                    {providerBadge()}
                    {isFirebaseEnabled && user?.emailVerified && (
                      <span className="flex items-center gap-1 px-1.5 py-0.5 text-[10px] font-medium bg-emerald-500/20 text-emerald-400 rounded">
                        <Shield className="w-3 h-3" />
                        Verified
                      </span>
                    )}
                  </div>
                </div>

                {/* Menu items */}
                <div className="p-2 border-t border-slate-700">
                  <button
                    onClick={() => {
                      setShowUserMenu(false)
                      navigate('/settings')
                    }}
                    className="flex items-center gap-3 w-full px-3 py-2.5 text-sm text-slate-300 hover:bg-slate-700 rounded-lg transition-colors"
                  >
                    <Settings className="w-4 h-4" />
                    <span>Settings</span>
                  </button>
                  <button
                    onClick={() => {
                      setShowUserMenu(false)
                      handleLogout()
                    }}
                    className="flex items-center gap-3 w-full px-3 py-2.5 text-sm text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
                  >
                    <LogOut className="w-4 h-4" />
                    <span>Sign Out</span>
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </header>
  )
}
