/**
 * CyberGuard AI — About Page (/about)
 * ============================================================================
 * Overview of the platform's mission, security architecture, privacy-first
 * design, and foundational security guarantees.
 */

import { useNavigate } from "react-router-dom";
import { ShieldCheck, Lock, Eye, CheckCircle2, ArrowRight, Award, HeartHandshake, Database } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import PublicNavbar from "@/components/public/PublicNavbar";
import PublicFooter from "@/components/public/PublicFooter";

export default function About() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100 flex flex-col font-sans">
      <PublicNavbar />

      <main className="flex-1 mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-12">
        {/* Header */}
        <div className="text-center max-w-3xl mx-auto space-y-4 mb-16">
          <span className="text-xs font-bold uppercase tracking-wider text-cyan-600 dark:text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-3 py-1 rounded-full">
            Our Mission & Principles
          </span>
          <h1 className="text-3xl sm:text-5xl font-black tracking-tight text-slate-900 dark:text-slate-100">
            Intelligent Defense for a Connected World
          </h1>
          <p className="text-base sm:text-lg text-slate-600 dark:text-slate-400">
            CyberGuard AI was engineered from the ground up to eliminate alert fatigue, democratize enterprise-grade defense, and connect frontline analysts with affected organizations.
          </p>
        </div>

        {/* Core Pillars */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-20">
          <Card className="bg-white/80 dark:bg-slate-900/80 border-slate-200 dark:border-slate-800 p-6 sm:p-8 space-y-4">
            <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-500 w-fit">
              <Lock size={24} />
            </div>
            <h2 className="text-xl font-bold text-slate-900 dark:text-slate-100">
              Zero-Trust Architecture
            </h2>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              Every request is authenticated, authorized, and logged. Role-based access control is enforced at the database and API level—never trusted from frontend state.
            </p>
          </Card>

          <Card className="bg-white/80 dark:bg-slate-900/80 border-slate-200 dark:border-slate-800 p-6 sm:p-8 space-y-4">
            <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-500 w-fit">
              <Eye size={24} />
            </div>
            <h2 className="text-xl font-bold text-slate-900 dark:text-slate-100">
              Forensic Verifiability
            </h2>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              Every security finding references concrete evidence: cryptographic file hashes, extracted URLs, MITRE ATT&CK techniques, and raw timestamped telemetry.
            </p>
          </Card>

          <Card className="bg-white/80 dark:bg-slate-900/80 border-slate-200 dark:border-slate-800 p-6 sm:p-8 space-y-4">
            <div className="p-3 rounded-xl bg-indigo-500/10 border border-indigo-500/30 text-indigo-500 w-fit">
              <HeartHandshake size={24} />
            </div>
            <h2 className="text-xl font-bold text-slate-900 dark:text-slate-100">
              Practitioner Community
            </h2>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              We bridge the talent gap by allowing independent cybersecurity professionals to verify their credentials and provide contracted investigation services directly to companies.
            </p>
          </Card>
        </div>

        {/* Compliance & Standards */}
        <div className="rounded-2xl border border-slate-200 bg-white/70 p-8 sm:p-12 dark:border-slate-800 dark:bg-slate-900/70 max-w-4xl mx-auto space-y-6 mb-16">
          <h2 className="text-2xl font-bold text-slate-900 dark:text-slate-100 text-center">
            Security & Governance Standards
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs text-slate-600 dark:text-slate-400">
            <div className="flex items-start gap-2.5">
              <CheckCircle2 size={16} className="text-emerald-500 shrink-0 mt-0.5" />
              <span><strong>TLS 1.3 Encryption:</strong> All data in transit is protected by strict TLS encryption with perfect forward secrecy.</span>
            </div>
            <div className="flex items-start gap-2.5">
              <CheckCircle2 size={16} className="text-emerald-500 shrink-0 mt-0.5" />
              <span><strong>AES-256 Storage:</strong> All telemetry and sensitive incident artifacts are encrypted at rest with hardware-backed keys.</span>
            </div>
            <div className="flex items-start gap-2.5">
              <CheckCircle2 size={16} className="text-emerald-500 shrink-0 mt-0.5" />
              <span><strong>Immutable Audit Logs:</strong> System state modifications are appended to write-only tamper-resistant logs.</span>
            </div>
            <div className="flex items-start gap-2.5">
              <CheckCircle2 size={16} className="text-emerald-500 shrink-0 mt-0.5" />
              <span><strong>Data Sovereignty:</strong> Users retain 100% ownership of their ingested telemetry and can trigger full data deletion at will.</span>
            </div>
          </div>
        </div>

        {/* CTA */}
        <div className="text-center py-6">
          <Button
            size="lg"
            variant="primary"
            onClick={() => navigate("/select-account")}
            className="text-sm font-bold shadow-md shadow-cyan-500/20"
          >
            Join CyberGuard AI <ArrowRight size={16} className="ml-1.5" />
          </Button>
        </div>
      </main>

      <PublicFooter />
    </div>
  );
}
