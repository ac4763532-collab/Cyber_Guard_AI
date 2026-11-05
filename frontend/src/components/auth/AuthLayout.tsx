/**
 * CyberGuard AI - Authentication Layout
 *
 * Premium split-screen layout for auth pages.
 * Left: Branding panel with subtle security visualization
 * Right: Authentication form
 */

import { ReactNode } from 'react'
import { Shield, Activity, Lock, Eye, Zap } from 'lucide-react'

interface AuthLayoutProps {
  children: ReactNode
  title?: string
  subtitle?: string
}

// Animated network node component
function NetworkNode({ className, delay }: { className: string; delay: number }) {
  return (
    <div
      className={`absolute w-2 h-2 bg-cyan-500/30 rounded-full ${className}`}
      style={{
        animation: `pulse 3s ease-in-out infinite`,
        animationDelay: `${delay}s`,
      }}
    >
      <div className="absolute inset-0 bg-cyan-400/50 rounded-full animate-ping" />
    </div>
  )
}

// Connection line between nodes
function ConnectionLine({ className }: { className: string }) {
  return (
    <div
      className={`absolute h-px bg-gradient-to-r from-transparent via-cyan-500/20 to-transparent ${className}`}
    />
  )
}

export function AuthLayout({ children, title, subtitle }: AuthLayoutProps) {
  return (
    <div className="min-h-screen flex bg-[#05070B]">
      {/* Left Panel - Branding */}
      <div className="hidden lg:flex lg:w-1/2 xl:w-[55%] relative overflow-hidden">
        {/* Background gradient */}
        <div className="absolute inset-0 bg-gradient-to-br from-slate-900 via-[#0a0f1a] to-[#05070B]" />

        {/* Subtle grid pattern */}
        <div
          className="absolute inset-0 opacity-[0.02]"
          style={{
            backgroundImage: `linear-gradient(rgba(255,255,255,0.1) 1px, transparent 1px),
                              linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px)`,
            backgroundSize: '60px 60px',
          }}
        />

        {/* Animated network visualization */}
        <div className="absolute inset-0">
          <NetworkNode className="top-[20%] left-[30%]" delay={0} />
          <NetworkNode className="top-[35%] left-[50%]" delay={0.5} />
          <NetworkNode className="top-[45%] left-[25%]" delay={1} />
          <NetworkNode className="top-[60%] left-[45%]" delay={1.5} />
          <NetworkNode className="top-[70%] left-[60%]" delay={2} />
          <NetworkNode className="top-[30%] left-[70%]" delay={0.3} />
          <NetworkNode className="top-[55%] left-[75%]" delay={1.2} />

          <ConnectionLine className="top-[25%] left-[32%] w-[18%] rotate-[25deg]" />
          <ConnectionLine className="top-[40%] left-[27%] w-[22%] -rotate-[15deg]" />
          <ConnectionLine className="top-[55%] left-[47%] w-[15%] rotate-[35deg]" />
          <ConnectionLine className="top-[35%] left-[52%] w-[18%] rotate-[5deg]" />
        </div>

        {/* Content */}
        <div className="relative z-10 flex flex-col justify-center px-12 xl:px-20">
          {/* Logo */}
          <div className="flex items-center gap-3 mb-8">
            <div className="flex items-center justify-center w-12 h-12 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-xl shadow-lg shadow-cyan-500/20">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white tracking-tight">CYBERGUARD AI</h1>
              <p className="text-[10px] font-medium text-cyan-400/80 tracking-[0.2em] uppercase">
                Security Operations Platform
              </p>
            </div>
          </div>

          {/* Tagline */}
          <div className="mb-10">
            <div className="flex flex-col gap-1 mb-6">
              <span className="text-4xl xl:text-5xl font-bold text-white">Detect.</span>
              <span className="text-4xl xl:text-5xl font-bold text-cyan-400">Correlate.</span>
              <span className="text-4xl xl:text-5xl font-bold text-white">Respond.</span>
            </div>
            <p className="text-slate-400 text-lg max-w-md leading-relaxed">
              AI-driven multi-agent threat detection and contextual security correlation for enterprise operations.
            </p>
          </div>

          {/* Features */}
          <div className="space-y-4">
            <Feature
              icon={<Activity className="w-4 h-4" />}
              title="Real-time Threat Detection"
              description="Multi-agent analysis across email, logs, and network"
            />
            <Feature
              icon={<Zap className="w-4 h-4" />}
              title="Cross-Domain Correlation"
              description="Intelligent linking of related security events"
            />
            <Feature
              icon={<Eye className="w-4 h-4" />}
              title="MITRE ATT&CK Mapping"
              description="Automated technique identification and enrichment"
            />
            <Feature
              icon={<Lock className="w-4 h-4" />}
              title="Incident Response"
              description="Guided remediation and compliance reporting"
            />
          </div>

          {/* Footer */}
          <div className="mt-12 pt-8 border-t border-slate-800/50">
            <p className="text-xs text-slate-600">
              Enterprise-grade security operations platform
            </p>
          </div>
        </div>
      </div>

      {/* Right Panel - Auth Form */}
      <div className="flex-1 flex flex-col justify-center px-6 sm:px-12 lg:px-16 xl:px-20">
        <div className="w-full max-w-md mx-auto">
          {/* Mobile logo */}
          <div className="lg:hidden flex items-center justify-center gap-3 mb-8">
            <div className="flex items-center justify-center w-12 h-12 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-xl">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-white">CYBERGUARD AI</h1>
            </div>
          </div>

          {/* Title */}
          {(title || subtitle) && (
            <div className="mb-8">
              {title && (
                <h2 className="text-2xl font-semibold text-white">{title}</h2>
              )}
              {subtitle && (
                <p className="mt-2 text-slate-400">{subtitle}</p>
              )}
            </div>
          )}

          {/* Auth form */}
          {children}
        </div>
      </div>

      {/* CSS for animations */}
      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 0.3; transform: scale(1); }
          50% { opacity: 0.6; transform: scale(1.2); }
        }
      `}</style>
    </div>
  )
}

// Feature item component
function Feature({
  icon,
  title,
  description,
}: {
  icon: ReactNode
  title: string
  description: string
}) {
  return (
    <div className="flex items-start gap-3">
      <div className="flex items-center justify-center w-8 h-8 bg-cyan-500/10 text-cyan-400 rounded-lg flex-shrink-0">
        {icon}
      </div>
      <div>
        <p className="text-sm font-medium text-white">{title}</p>
        <p className="text-xs text-slate-500">{description}</p>
      </div>
    </div>
  )
}
