/**
 * CyberGuard AI — Public Header & Navigation
 * ============================================================================
 * Production-grade responsive public navbar with:
 * - Brand logo linking to "/"
 * - Nav links for Home, Features, How It Works, Solutions, Pricing, About
 * - Functional Sign In (/login) and Get Started (/select-account)
 * - Mobile hamburger menu toggle with active states
 */

import { useState } from "react";
import { Link, NavLink, useNavigate } from "react-router-dom";
import { ShieldCheck, Menu, X, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { cn } from "@/lib/utils";

export const publicNavLinks = [
  { label: "Home", href: "/" },
  { label: "Features", href: "/features" },
  { label: "How It Works", href: "/how-it-works" },
  { label: "Solutions", href: "/solutions" },
  { label: "Pricing", href: "/pricing" },
  { label: "About", href: "/about" },
];

export function PublicNavbar() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const navigate = useNavigate();

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-200/80 bg-slate-50/90 backdrop-blur-md dark:border-slate-800/80 dark:bg-slate-950/90">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        
        {/* ── Brand Logo ────────────────────────────────────────────── */}
        <Link
          to="/"
          className="flex items-center gap-2.5 transition-transform hover:scale-[1.02] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 rounded-lg p-1"
        >
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-brand-500/10 border border-brand-500/30 text-cyan-500 shadow-[0_0_12px_rgba(6,182,212,0.2)]">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <div className="flex flex-col">
            <span className="text-base font-extrabold tracking-wider text-slate-900 dark:text-slate-100">
              CYBER<span className="text-cyan-500 dark:text-cyan-400">GUARD</span>
            </span>
            <span className="text-[9px] font-semibold uppercase tracking-widest text-slate-500 dark:text-slate-400 -mt-0.5">
              AI Defense Platform
            </span>
          </div>
        </Link>

        {/* ── Desktop Navigation ────────────────────────────────────── */}
        <nav className="hidden md:flex items-center gap-1 lg:gap-2">
          {publicNavLinks.map((link) => (
            <NavLink
              key={link.label}
              to={link.href}
              className={({ isActive }) =>
                cn(
                  "px-3 py-1.5 text-xs lg:text-sm font-semibold rounded-lg transition-colors duration-150",
                  isActive
                    ? "bg-slate-200/80 text-brand-600 dark:bg-slate-900 dark:text-cyan-400 font-bold"
                    : "text-slate-600 hover:text-slate-900 hover:bg-slate-200/50 dark:text-slate-300 dark:hover:text-slate-100 dark:hover:bg-slate-900/60"
                )
              }
            >
              {link.label}
            </NavLink>
          ))}
        </nav>

        {/* ── Desktop Auth Actions ──────────────────────────────────── */}
        <div className="hidden sm:flex items-center gap-3">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => navigate("/login")}
            className="text-xs font-semibold text-slate-700 dark:text-slate-200 hover:text-brand-600 dark:hover:text-cyan-400"
          >
            Sign In
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={() => navigate("/select-account")}
            className="text-xs font-bold shadow-sm shadow-cyan-500/20"
          >
            Get Started <ArrowRight size={14} className="ml-1" />
          </Button>
        </div>

        {/* ── Mobile Menu Trigger ───────────────────────────────────── */}
        <div className="flex sm:hidden items-center gap-2">
          <Button
            variant="primary"
            size="sm"
            onClick={() => navigate("/select-account")}
            className="text-xs px-2.5 h-8"
          >
            Get Started
          </Button>
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="p-2 rounded-lg text-slate-600 hover:text-slate-900 hover:bg-slate-200/60 dark:text-slate-300 dark:hover:text-slate-100 dark:hover:bg-slate-900 transition"
            aria-label="Toggle Navigation Menu"
          >
            {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>
      </div>

      {/* ── Mobile Menu Dropdown ──────────────────────────────────────── */}
      {mobileMenuOpen && (
        <div className="md:hidden border-b border-slate-200 bg-slate-50 dark:border-slate-800 dark:bg-slate-950 px-4 py-4 space-y-2 animate-in slide-in-from-top-2 duration-150">
          <div className="flex flex-col space-y-1">
            {publicNavLinks.map((link) => (
              <NavLink
                key={link.label}
                to={link.href}
                onClick={() => setMobileMenuOpen(false)}
                className={({ isActive }) =>
                  cn(
                    "px-3 py-2 rounded-lg text-sm font-semibold transition-colors",
                    isActive
                      ? "bg-slate-200 text-brand-600 dark:bg-slate-900 dark:text-cyan-400"
                      : "text-slate-600 hover:bg-slate-200/60 dark:text-slate-300 dark:hover:bg-slate-900"
                  )
                }
              >
                {link.label}
              </NavLink>
            ))}
          </div>

          <div className="pt-3 border-t border-slate-200 dark:border-slate-800 flex flex-col gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setMobileMenuOpen(false);
                navigate("/login");
              }}
              className="w-full text-xs font-semibold justify-center"
            >
              Sign In to Account
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={() => {
                setMobileMenuOpen(false);
                navigate("/select-account");
              }}
              className="w-full text-xs font-bold justify-center"
            >
              Get Started Free
            </Button>
          </div>
        </div>
      )}
    </header>
  );
}

export default PublicNavbar;
