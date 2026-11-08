/**
 * CyberGuard AI — Public Footer
 * ============================================================================
 * Production-grade public footer with functional React Router Links.
 */

import { Link } from "react-router-dom";
import { ShieldCheck, Heart } from "lucide-react";

export function PublicFooter() {
  return (
    <footer className="mt-20 border-t border-slate-200 bg-white/50 dark:border-slate-800 dark:bg-slate-950/80">
      <div className="mx-auto max-w-7xl px-4 py-12 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 gap-8 md:grid-cols-4">
          
          {/* Brand Col */}
          <div className="space-y-4">
            <Link to="/" className="flex items-center gap-2">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-500/10 border border-brand-500/30 text-cyan-500">
                <ShieldCheck className="h-5 w-5" />
              </div>
              <span className="font-extrabold text-base tracking-wider text-slate-900 dark:text-slate-100">
                CYBER<span className="text-cyan-500 dark:text-cyan-400">GUARD</span>
              </span>
            </Link>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed max-w-xs">
              Autonomous multi-agent threat detection, correlation, and response platform for individuals, analysts, and enterprise organizations.
            </p>
          </div>

          {/* Navigation Links */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-slate-200 mb-3">
              Platform
            </h4>
            <ul className="space-y-2 text-xs text-slate-600 dark:text-slate-400">
              <li>
                <Link to="/" className="hover:text-cyan-500 transition-colors">Home</Link>
              </li>
              <li>
                <Link to="/features" className="hover:text-cyan-500 transition-colors">AI Security Agents</Link>
              </li>
              <li>
                <Link to="/how-it-works" className="hover:text-cyan-500 transition-colors">Architecture & Pipeline</Link>
              </li>
              <li>
                <Link to="/pricing" className="hover:text-cyan-500 transition-colors">Plans & Pricing</Link>
              </li>
              <li>
                <Link to="/about" className="hover:text-cyan-500 transition-colors">About CyberGuard</Link>
              </li>
            </ul>
          </div>

          {/* Solutions Links */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-slate-200 mb-3">
              Solutions
            </h4>
            <ul className="space-y-2 text-xs text-slate-600 dark:text-slate-400">
              <li>
                <Link to="/solutions" className="hover:text-cyan-500 transition-colors">All Workspaces</Link>
              </li>
              <li>
                <Link to="/register?type=individual" className="hover:text-cyan-500 transition-colors">Personal Protection</Link>
              </li>
              <li>
                <Link to="/analyst/register" className="hover:text-cyan-500 transition-colors">Security Analyst Portal</Link>
              </li>
              <li>
                <Link to="/organization/create" className="hover:text-cyan-500 transition-colors">Enterprise Organizations</Link>
              </li>
              <li>
                <Link to="/select-account" className="hover:text-cyan-500 transition-colors">Account Type Selector</Link>
              </li>
            </ul>
          </div>

          {/* Account & Legal */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-slate-200 mb-3">
              Account & Legal
            </h4>
            <ul className="space-y-2 text-xs text-slate-600 dark:text-slate-400">
              <li>
                <Link to="/login" className="hover:text-cyan-500 transition-colors">Account Sign In</Link>
              </li>
              <li>
                <Link to="/terms" className="hover:text-cyan-500 transition-colors">Terms of Service</Link>
              </li>
              <li>
                <Link to="/privacy" className="hover:text-cyan-500 transition-colors">Privacy Policy</Link>
              </li>
            </ul>
          </div>

        </div>

        <div className="mt-10 pt-6 border-t border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-500">
          <p>&copy; {new Date().getFullYear()} CyberGuard AI. All rights reserved. Zero-Trust Multi-Agent Defense.</p>
          <div className="flex items-center gap-1 text-slate-400">
            <span>Built for rigorous cybersecurity operations</span>
          </div>
        </div>
      </div>
    </footer>
  );
}

export default PublicFooter;
