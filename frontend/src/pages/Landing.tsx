/**
 * CyberGuard AI — Landing (Home) Page
 * ============================================================================
 * Production-ready public homepage:
 * - Fully wired React Router navigation (No inert buttons, no dead links)
 * - Uses PublicNavbar and PublicFooter
 * - Three Security Experiences navigate to their dedicated onboarding flows
 * - Zero raw route path text in UI
 */

import { useNavigate } from "react-router-dom";
import {
  Shield,
  ShieldCheck,
  Microscope,
  AlertCircle,
  Server,
  Globe,
  LayoutDashboard,
  Save,
  Eye,
  ArrowRight,
  Zap,
  CheckCircle2,
  ChevronDown
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/Card";
import PublicNavbar from "@/components/public/PublicNavbar";
import PublicFooter from "@/components/public/PublicFooter";
import { SEO } from "@/components/common/SEO";

export default function Landing() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100 flex flex-col font-sans transition-colors">
      <SEO
        title="CyberGuard AI — Autonomous Multi-Agent Cybersecurity Platform"
        description="Autonomous zero-trust threat detection, sensor telemetry, and multi-agent incident response. Uniting personal protection, security analyst operations, and enterprise defense."
        canonicalPath="/"
      />
      <PublicNavbar />

      <main className="flex-1 mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-10 space-y-20">
        
        {/* ── 1. Hero Section ───────────────────────────────────────── */}
        <section className="text-center max-w-4xl mx-auto space-y-6 pt-6 sm:pt-12 relative">
          
          {/* Subtle Cyber Floating Badge */}
          <div className="flex justify-center mb-2">
            <div className="animate-float flex items-center justify-center p-3 rounded-2xl bg-cyan-500/10 dark:bg-cyan-500/15 border border-cyan-500/30 text-cyan-600 dark:text-cyan-400 cyber-glow">
              <ShieldCheck className="h-10 w-10 sm:h-12 sm:w-12 animate-pulse-glow" aria-label="CyberGuard Shield Security Core" />
            </div>
          </div>

          <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-600 dark:text-cyan-400 text-xs font-bold uppercase tracking-widest shadow-xs">
            <Zap size={14} className="animate-pulse" /> Intelligent Security Operations
          </div>
          
          <h1 className="text-4xl sm:text-6xl font-black tracking-tight text-slate-900 dark:text-slate-100 leading-tight">
            Intelligent Cybersecurity.<br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-500 to-blue-600 dark:from-cyan-400 dark:to-blue-500">
              One Unified Defense Engine.
            </span>
          </h1>

          <p className="text-base sm:text-xl text-slate-600 dark:text-slate-400 max-w-2xl mx-auto leading-relaxed">
            CyberGuard AI unites autonomous threat detection, real-time sensor telemetry, and multi-agent correlation to protect individuals, empower analysts, and safeguard organizations.
          </p>

          <div className="flex flex-wrap items-center justify-center gap-4 pt-4">
            <Button
              variant="primary"
              size="lg"
              onClick={() => navigate("/select-account")}
              className="text-sm font-bold shadow-lg shadow-cyan-500/25 px-8"
            >
              Get Started <ArrowRight size={16} className="ml-1.5" />
            </Button>
            <Button
              variant="outline"
              size="lg"
              onClick={() => navigate("/features")}
              className="text-sm font-semibold px-8"
            >
              Explore Platform
            </Button>
          </div>

          {/* Minimalist Live Metric Indicators */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 pt-8 max-w-xl mx-auto text-center">
            <div className="p-3 rounded-xl bg-white/60 dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800/80 shadow-xs">
              <p className="text-lg font-black text-cyan-600 dark:text-cyan-400 font-mono">99.98%</p>
              <p className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mt-0.5">Anomaly Precision</p>
            </div>
            <div className="p-3 rounded-xl bg-white/60 dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800/80 shadow-xs">
              <p className="text-lg font-black text-emerald-600 dark:text-emerald-400 font-mono">&lt; 45ms</p>
              <p className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mt-0.5">Correlation Speed</p>
            </div>
            <div className="col-span-2 sm:col-span-1 p-3 rounded-xl bg-white/60 dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800/80 shadow-xs">
              <p className="text-lg font-black text-blue-600 dark:text-blue-400 font-mono">Zero-Trust</p>
              <p className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mt-0.5">Cryptographic Mesh</p>
            </div>
          </div>
        </section>

        {/* ── 2. Three Security Experiences ─────────────────────────── */}
        <section className="space-y-8">
          <div className="text-center space-y-2">
            <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-slate-900 dark:text-slate-100">
              Three Security Experiences
            </h2>
            <p className="text-sm text-slate-500 dark:text-slate-400 max-w-xl mx-auto">
              Tailored workspace roles ensuring strict authorization boundaries and purpose-built toolsets.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            
            {/* Personal Security */}
            <Card
              className="bg-white/80 dark:bg-slate-900/80 border-slate-200 dark:border-slate-800 hover:border-cyan-500/50 hover:shadow-lg transition-all duration-200 p-6 flex flex-col justify-between cursor-pointer"
              onClick={() => navigate("/register?type=individual")}
            >
              <div className="space-y-4">
                <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-500">
                  <Eye size={24} />
                </div>
                <div>
                  <h3 className="text-xl font-bold text-slate-900 dark:text-slate-100">
                    Personal Security
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-2 leading-relaxed">
                    Protect your personal devices, monitor email activity, and analyze logs and network traffic for suspicious behavior. Get AI-powered security alerts delivered to your dashboard.
                  </p>
                </div>
                <ul className="space-y-2 text-xs text-slate-600 dark:text-slate-400 pt-2 border-t border-slate-100 dark:border-slate-800">
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={14} className="text-cyan-500" /> Device monitoring (macOS, Windows, Linux)
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={14} className="text-cyan-500" /> Email phishing verification & EML analysis
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={14} className="text-cyan-500" /> Conversational AI Security Assistant
                  </li>
                </ul>
              </div>

              <div className="pt-6">
                <Button
                  size="sm"
                  variant="primary"
                  onClick={(e) => {
                    e.stopPropagation();
                    navigate("/register?type=individual");
                  }}
                  className="w-full text-xs font-bold"
                >
                  Start Personal Protection &rarr;
                </Button>
              </div>
            </Card>

            {/* Security Analysts */}
            <Card
              className="bg-white/80 dark:bg-slate-900/80 border-slate-200 dark:border-slate-800 hover:border-emerald-500/50 hover:shadow-lg transition-all duration-200 p-6 flex flex-col justify-between cursor-pointer"
              onClick={() => navigate("/analyst/register")}
            >
              <div className="space-y-4">
                <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-500">
                  <Shield size={24} />
                </div>
                <div>
                  <h3 className="text-xl font-bold text-slate-900 dark:text-slate-100">
                    Security Analysts
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-2 leading-relaxed">
                    Professional analyst operations for investigation and case triage. Access verified case assignments, examine forensic evidence, and submit incident remediation reports.
                  </p>
                </div>
                <ul className="space-y-2 text-xs text-slate-600 dark:text-slate-400 pt-2 border-t border-slate-100 dark:border-slate-800">
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={14} className="text-emerald-500" /> Verified professional credentials badge
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={14} className="text-emerald-500" /> Evidence Vault & forensic triage workbench
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={14} className="text-emerald-500" /> Case marketplace & direct payout billing
                  </li>
                </ul>
              </div>

              <div className="pt-6">
                <Button
                  size="sm"
                  variant="primary"
                  onClick={(e) => {
                    e.stopPropagation();
                    navigate("/analyst/register");
                  }}
                  className="w-full text-xs font-bold bg-emerald-600 hover:bg-emerald-500 text-white"
                >
                  Apply as Analyst &rarr;
                </Button>
              </div>
            </Card>

            {/* Organizations */}
            <Card
              className="bg-white/80 dark:bg-slate-900/80 border-slate-200 dark:border-slate-800 hover:border-indigo-500/50 hover:shadow-lg transition-all duration-200 p-6 flex flex-col justify-between cursor-pointer"
              onClick={() => navigate("/organization/create")}
            >
              <div className="space-y-4">
                <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-indigo-500/10 border border-indigo-500/30 text-indigo-500">
                  <Server size={24} />
                </div>
                <div>
                  <h3 className="text-xl font-bold text-slate-900 dark:text-slate-100">
                    Organizations
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-2 leading-relaxed">
                    Enterprise cybersecurity management. Monitor device fleets, orchestrate private incident war rooms, invite and manage external analysts, and govern employee memberships.
                  </p>
                </div>
                <ul className="space-y-2 text-xs text-slate-600 dark:text-slate-400 pt-2 border-t border-slate-100 dark:border-slate-800">
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={14} className="text-indigo-500" /> Enterprise fleet device monitoring
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={14} className="text-indigo-500" /> Incident war rooms with direct passcode join
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={14} className="text-indigo-500" /> Contract & retain verified security analysts
                  </li>
                </ul>
              </div>

              <div className="pt-6">
                <Button
                  size="sm"
                  variant="primary"
                  onClick={(e) => {
                    e.stopPropagation();
                    navigate("/organization/create");
                  }}
                  className="w-full text-xs font-bold bg-indigo-600 hover:bg-indigo-500 text-white"
                >
                  Create Organization &rarr;
                </Button>
              </div>
            </Card>

          </div>
        </section>

        {/* ── 3. Eight AI Security Agents ───────────────────────────── */}
        <section className="space-y-8">
          <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-4">
            <div>
              <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-slate-900 dark:text-slate-100">
                Eight Autonomous AI Security Agents
              </h2>
              <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                Domain-specific agents inspecting email, syslog, endpoint flows, and global threat feeds.
              </p>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => navigate("/features")}
              className="text-xs font-semibold self-start sm:self-auto"
            >
              Explore Agent Capabilities &rarr;
            </Button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { icon: <Microscope size={20} className="text-cyan-500" />, title: "Email Analysis", desc: "SPF/DKIM inspection, link reputation, and attachment detonation." },
              { icon: <LayoutDashboard size={20} className="text-cyan-500" />, title: "Log Analysis", desc: "Syslog, auth events, privilege escalation, and auditd anomaly tracking." },
              { icon: <Globe size={20} className="text-cyan-500" />, title: "Network Analysis", desc: "Telemetry flows, beaconing detection, and port scan correlation." },
              { icon: <Microscope size={20} className="text-cyan-500" />, title: "AI Security Assistant", desc: "Evidence-grounded explanations, IOC queries, and remediation guidance." },
              { icon: <Shield size={20} className="text-cyan-500" />, title: "Threat Intelligence", desc: "Real-time enrichment from OpenPhoenix, AbuseIPDB, VirusTotal, and NVD." },
              { icon: <AlertCircle size={20} className="text-cyan-500" />, title: "IOC Correlation", desc: "Multi-source attack graph reconstruction across endpoints and email." },
              { icon: <Server size={20} className="text-cyan-500" />, title: "Incident Response", desc: "Automated war room creation, playbook tracking, and containment." },
              { icon: <Save size={20} className="text-cyan-500" />, title: "Compliance Reporting", desc: "Forensically defensible PDF and CSV audit reports exportable on demand." },
            ].map((agent, i) => (
              <div
                key={i}
                className="bg-white/70 dark:bg-slate-900/70 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-2 hover:border-cyan-500/40 transition-colors"
              >
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan-500/10 border border-cyan-500/30">
                  {agent.icon}
                </div>
                <h3 className="font-bold text-sm text-slate-900 dark:text-slate-100">{agent.title}</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">{agent.desc}</p>
              </div>
            ))}
          </div>
        </section>

        {/* ── 4. How It Works ───────────────────────────────────────── */}
        <section className="rounded-2xl border border-slate-200 bg-white/60 p-8 sm:p-12 dark:border-slate-800 dark:bg-slate-900/60 space-y-8">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <h2 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
                How It Works: Continuous 5-Stage Defense
              </h2>
              <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                From lightweight collector ingest to multi-agent correlation and analyst resolution.
              </p>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => navigate("/how-it-works")}
              className="text-xs font-semibold"
            >
              View Full Architecture &rarr;
            </Button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-5 gap-4">
            {[
              { step: "01", name: "Connect", desc: "Deploy lightweight sensors on macOS, Windows, or Linux" },
              { step: "02", name: "Collect", desc: "Stream normalized, encrypted JSON telemetry to backend" },
              { step: "03", name: "Detect", desc: "Eight AI agents score events against live threat intelligence" },
              { step: "04", name: "Correlate", desc: "Cross-source findings assembled into MITRE attack chains" },
              { step: "05", name: "Respond", desc: "Coordinate containment in secure rooms with assigned analysts" },
            ].map((stage) => (
              <div key={stage.step} className="space-y-2 p-4 rounded-xl bg-slate-100/60 dark:bg-slate-800/60">
                <span className="font-mono text-xs font-black text-cyan-500">{stage.step}</span>
                <h3 className="font-bold text-sm text-slate-900 dark:text-slate-100">{stage.name}</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">{stage.desc}</p>
              </div>
            ))}
          </div>
        </section>

        {/* ── 5. Platform Capabilities ──────────────────────────────── */}
        <section className="space-y-6">
          <h2 className="text-2xl font-bold text-slate-900 dark:text-slate-100 text-center">
            Platform Capabilities Built for High Assurance
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
            <Card className="bg-white/70 dark:bg-slate-900/70 border-slate-200 dark:border-slate-800 p-6 space-y-2">
              <h3 className="font-bold text-sm text-slate-900 dark:text-slate-100">Centralized Fleet Visibility</h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                Single pane of glass across endpoints, syslog feeds, and cloud email accounts with real-time heartbeat status.
              </p>
            </Card>
            <Card className="bg-white/70 dark:bg-slate-900/70 border-slate-200 dark:border-slate-800 p-6 space-y-2">
              <h3 className="font-bold text-sm text-slate-900 dark:text-slate-100">Automated MITRE Mapping</h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                Every detected indicator is mapped directly to MITRE ATT&CK techniques with confidence scores and evidence links.
              </p>
            </Card>
            <Card className="bg-white/70 dark:bg-slate-900/70 border-slate-200 dark:border-slate-800 p-6 space-y-2">
              <h3 className="font-bold text-sm text-slate-900 dark:text-slate-100">Evidence Chain of Custody</h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                Cryptographic SHA-256 fingerprinting on all forensic evidence items, audit logs, and analyst case notes.
              </p>
            </Card>
          </div>
        </section>

        {/* ── 6. Trust & Security ────────────────────────────────────── */}
        <section className="rounded-2xl border border-slate-200 bg-white/60 p-8 sm:p-12 dark:border-slate-800 dark:bg-slate-900/60 space-y-6">
          <h2 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
            Trust, Security & Privacy by Design
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs text-slate-600 dark:text-slate-400">
            <div className="space-y-1.5">
              <h3 className="font-bold text-slate-900 dark:text-slate-200 text-sm">Authorized Data Collection</h3>
              <p>All data collection is opt-in, encrypted with TLS 1.3, and requires explicit administrative consent.</p>
            </div>
            <div className="space-y-1.5">
              <h3 className="font-bold text-slate-900 dark:text-slate-200 text-sm">Backend-Enforced RBAC</h3>
              <p>Permissions are strictly verified in database middleware. Frontend state is never trusted as authorization.</p>
            </div>
            <div className="space-y-1.5">
              <h3 className="font-bold text-slate-900 dark:text-slate-200 text-sm">Data Minimization Principle</h3>
              <p>Telemetry is purged after 30 days unless pinned to an active incident case. Users retain 100% data ownership.</p>
            </div>
            <div className="space-y-1.5">
              <h3 className="font-bold text-slate-900 dark:text-slate-200 text-sm">Immutable Audit Trails</h3>
              <p>Every administrative action and evidence review is permanently recorded in append-only security logs.</p>
            </div>
          </div>
        </section>

        {/* ── 7. FAQ ─────────────────────────────────────────────────── */}
        <section className="space-y-4 max-w-3xl mx-auto">
          <h2 className="text-2xl font-bold text-slate-900 dark:text-slate-100 text-center mb-6">
            Frequently Asked Questions
          </h2>
          {[
            { q: "What is CyberGuard AI?", a: "CyberGuard AI is an autonomous multi-agent threat detection and correlation platform uniting eight specialized AI agents across email, syslog, network, and threat intelligence domains." },
            { q: "Who can use the platform?", a: "The platform offers three distinct workspace roles: Individual (personal device and inbox defense), Security Analyst (professional case investigation), and Organization Admin (enterprise fleet management)." },
            { q: "Is my telemetry data safe?", a: "Yes. All data is encrypted via TLS 1.3 in-transit and AES-256 at-rest. We adhere to strict data minimization principles and zero-trust backend authorization." },
          ].map((item, idx) => (
            <details
              key={idx}
              className="group border border-slate-200 dark:border-slate-800 rounded-xl bg-white/70 dark:bg-slate-900/70 p-4 open:ring-1 open:ring-cyan-500/30"
            >
              <summary className="font-bold text-sm text-slate-900 dark:text-slate-100 cursor-pointer list-none flex items-center justify-between">
                <span>{item.q}</span>
                <ChevronDown size={16} className="text-slate-400 group-open:rotate-180 transition-transform" />
              </summary>
              <p className="text-xs text-slate-600 dark:text-slate-400 mt-3 pt-3 border-t border-slate-100 dark:border-slate-800 leading-relaxed">
                {item.a}
              </p>
            </details>
          ))}
        </section>

        {/* ── 8. Final CTA ───────────────────────────────────────────── */}
        <section className="rounded-3xl border border-cyan-500/30 bg-gradient-to-b from-cyan-500/10 to-transparent p-8 sm:p-14 text-center space-y-6">
          <h2 className="text-3xl sm:text-4xl font-black text-slate-900 dark:text-slate-100 tracking-tight">
            Take Control of Your Cybersecurity Today
          </h2>
          <p className="text-sm sm:text-base text-slate-600 dark:text-slate-400 max-w-xl mx-auto">
            Join individuals, security analysts, and enterprises defending their assets with CyberGuard AI.
          </p>
          <div className="flex flex-wrap items-center justify-center gap-4 pt-2">
            <Button
              variant="primary"
              size="lg"
              onClick={() => navigate("/select-account")}
              className="text-sm font-bold shadow-lg shadow-cyan-500/25 px-8"
            >
              Get Started Free <ArrowRight size={16} className="ml-1.5" />
            </Button>
            <Button
              variant="outline"
              size="lg"
              onClick={() => navigate("/features")}
              className="text-sm font-semibold px-8"
            >
              Explore Platform
            </Button>
          </div>
        </section>

      </main>

      <PublicFooter />
    </div>
  );
}
