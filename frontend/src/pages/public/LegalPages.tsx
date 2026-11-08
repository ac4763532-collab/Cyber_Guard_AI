/**
 * CyberGuard AI — Terms of Service & Privacy Policy (/terms, /privacy)
 * ============================================================================
 */

import { Link } from "react-router-dom";
import { ArrowLeft, ShieldCheck } from "lucide-react";
import PublicNavbar from "@/components/public/PublicNavbar";
import PublicFooter from "@/components/public/PublicFooter";
import { Button } from "@/components/ui/Button";

export function Terms() {
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100 flex flex-col font-sans">
      <PublicNavbar />
      <main className="flex-1 mx-auto max-w-4xl px-4 py-12 space-y-8">
        <Link to="/" className="inline-flex items-center gap-1.5 text-xs text-cyan-600 dark:text-cyan-400 hover:underline">
          <ArrowLeft size={14} /> Back to Home
        </Link>
        <h1 className="text-3xl font-black text-slate-900 dark:text-slate-100">
          Terms of Service
        </h1>
        <p className="text-xs text-slate-500">Effective Date: November 2026</p>
        <div className="space-y-6 text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
          <section className="space-y-2">
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-200">1. Acceptance of Terms</h2>
            <p>By creating an account or accessing CyberGuard AI, you agree to these Terms. If you represent an organization, you affirm that you possess full administrative authority to bind that entity.</p>
          </section>
          <section className="space-y-2">
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-200">2. Permitted Security Operations</h2>
            <p>You agree to deploy collectors, upload EML samples, and perform vulnerability diagnostics solely on assets, networks, and inboxes that you legally own or are explicitly authorized in writing to assess.</p>
          </section>
          <section className="space-y-2">
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-200">3. Multi-Agent AI Analysis</h2>
            <p>CyberGuard AI agents provide heuristic, statistical, and threat-intel correlation. While engineered to maximize precision and eliminate false positives, all findings should be verified prior to destructive containment actions.</p>
          </section>
          <section className="space-y-2">
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-200">4. Independent Analyst Engagements</h2>
            <p>Analyst-client consultations through CyberGuard AI rooms are governed by our platform code of conduct. Analysts maintain professional confidentiality regarding all shared telemetry.</p>
          </section>
        </div>
      </main>
      <PublicFooter />
    </div>
  );
}

export function Privacy() {
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100 flex flex-col font-sans">
      <PublicNavbar />
      <main className="flex-1 mx-auto max-w-4xl px-4 py-12 space-y-8">
        <Link to="/" className="inline-flex items-center gap-1.5 text-xs text-cyan-600 dark:text-cyan-400 hover:underline">
          <ArrowLeft size={14} /> Back to Home
        </Link>
        <h1 className="text-3xl font-black text-slate-900 dark:text-slate-100">
          Privacy Policy
        </h1>
        <p className="text-xs text-slate-500">Effective Date: November 2026</p>
        <div className="space-y-6 text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
          <section className="space-y-2">
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-200">1. Data Minimization Principle</h2>
            <p>CyberGuard AI collects only telemetry strictly required for cyber defense: process execution hashes, connection metadata, and normalized log headers. We never inspect or retain personal document contents.</p>
          </section>
          <section className="space-y-2">
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-200">2. Encryption at Rest & In-Transit</h2>
            <p>All telemetry streams require TLS 1.3 encryption. Stored incident records and forensic artifacts are encrypted with AES-256 with hardware key isolation.</p>
          </section>
          <section className="space-y-2">
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-200">3. Data Retention & Deletion</h2>
            <p>Non-incident raw telemetry is automatically purged after 30 days unless pinned to an active forensic investigation case. You may request immediate deletion of your workspace data at any time.</p>
          </section>
        </div>
      </main>
      <PublicFooter />
    </div>
  );
}
