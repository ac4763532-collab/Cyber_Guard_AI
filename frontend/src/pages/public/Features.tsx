/**
 * CyberGuard AI — Features Page (/features)
 * ============================================================================
 * Deep dive into the Eight AI Security Agents, Multi-Agent Threat Detection,
 * Telemetry Ingestion, and Automated Incident Investigation.
 */

import { useNavigate } from "react-router-dom";
import { 
  Shield, 
  Mail, 
  Terminal, 
  Wifi, 
  Bot, 
  Globe2, 
  Share2, 
  AlertTriangle, 
  FileText,
  ArrowRight,
  CheckCircle2,
  Zap,
  Lock,
  Cpu
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/Card";
import PublicNavbar from "@/components/public/PublicNavbar";
import PublicFooter from "@/components/public/PublicFooter";
import { SEO } from "@/components/common/SEO";

const agents = [
  {
    icon: <Mail className="w-6 h-6 text-cyan-400" />,
    name: "Email Analysis Agent",
    tagline: "Phishing & Malicious Attachment Detection",
    description: "Evaluates raw EML telemetry, validates SPF/DKIM/DMARC records, inspects embedded hyperlinks against threat intel, and neutralizes social engineering exploits."
  },
  {
    icon: <Terminal className="w-6 h-6 text-cyan-400" />,
    name: "Log Analysis Agent",
    tagline: "High-Throughput Syslog & Audit Ingestion",
    description: "Correlates authentication anomalies, privilege escalation patterns, brute force logins, and Windows Event / Linux auditd event streams in near-real-time."
  },
  {
    icon: <Wifi className="w-6 h-6 text-cyan-400" />,
    name: "Network Security Agent",
    tagline: "Endpoint Telemetry & Flow Monitoring",
    description: "Monitors outbound connections, anomalous beaconing patterns, unauthorized port listening, DNS tunneling attempts, and network perimeter posture."
  },
  {
    icon: <Bot className="w-6 h-6 text-cyan-400" />,
    name: "AI Security Assistant",
    tagline: "Evidence-Grounded Conversational Analyst",
    description: "Interactively answers threat queries, summarizes active security cases, contextualizes CVE vulnerabilities, and suggests remediation playbooks."
  },
  {
    icon: <Globe2 className="w-6 h-6 text-cyan-400" />,
    name: "Threat Intelligence Agent",
    tagline: "Global Indicator Enrichment (IOCs)",
    description: "Integrates OpenPhoenix, AbuseIPDB, VirusTotal, and NVD feeds to enrich every raw event with reputational scoring, geolocation, and threat actor profiling."
  },
  {
    icon: <Share2 className="w-6 h-6 text-cyan-400" />,
    name: "IOC Correlation Agent",
    tagline: "Multi-Source Attack Chain Reconstruction",
    description: "Links disparate indicators across email, network, and endpoints to assemble multi-stage MITRE ATT&CK kill-chains and eliminate false-positive alert fatigue."
  },
  {
    icon: <AlertTriangle className="w-6 h-6 text-cyan-400" />,
    name: "Incident Response Agent",
    tagline: "Automated Containment & Triage",
    description: "Executes rule-based containment actions, provisions isolated security rooms, coordinates analyst assignment, and tracks eradication lifecycles."
  },
  {
    icon: <FileText className="w-6 h-6 text-cyan-400" />,
    name: "Reporting Agent",
    tagline: "Evidence-Backed Audit & Executive Reports",
    description: "Synthesizes forensic timelines, analyst notes, and compliance metrics into cryptographically signed PDF and CSV reports for stakeholders."
  }
];

export default function Features() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100 flex flex-col font-sans transition-colors">
      <SEO
        title="AI Security Agents & Features — CyberGuard AI"
        description="Explore the eight specialist AI agents powering CyberGuard AI: email threat analysis, syslog telemetry, network flow inspection, IOC correlation, and automated containment."
        canonicalPath="/features"
      />
      <PublicNavbar />

      <main className="flex-1 mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-12">
        {/* ── Hero Header ─────────────────────────────────────────────── */}
        <div className="text-center max-w-3xl mx-auto space-y-4 mb-16">
          <span className="text-xs font-bold uppercase tracking-wider text-cyan-600 dark:text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-3 py-1 rounded-full">
            Autonomous Multi-Agent Architecture
          </span>
          <h1 className="text-3xl sm:text-5xl font-black tracking-tight text-slate-900 dark:text-slate-100">
            Eight Specialist AI Agents.<br/>One Unified Defense Engine.
          </h1>
          <p className="text-base sm:text-lg text-slate-600 dark:text-slate-400">
            Unlike fragmented security tools, CyberGuard AI deploys eight specialized agents that operate in tandem to ingest, correlate, and investigate cyber threats in real time.
          </p>

          <div className="flex flex-wrap items-center justify-center gap-4 pt-4">
            <Button
              size="lg"
              variant="primary"
              onClick={() => navigate("/select-account")}
              className="text-sm font-bold shadow-lg shadow-cyan-500/20"
            >
              Get Started with CyberGuard <ArrowRight size={16} className="ml-1.5" />
            </Button>
            <Button
              size="lg"
              variant="outline"
              onClick={() => navigate("/how-it-works")}
              className="text-sm font-semibold"
            >
              Explore Architecture
            </Button>
          </div>
        </div>

        {/* ── Eight Agents Grid ────────────────────────────────────────── */}
        <section className="mb-20">
          <div className="text-center mb-10">
            <h2 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
              The Eight Specialized AI Defense Agents
            </h2>
            <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
              Every agent specializes in a distinct security domain with coordinated cross-agent correlation.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {agents.map((agent) => (
              <Card
                key={agent.name}
                className="bg-white/70 dark:bg-slate-900/70 border-slate-200 dark:border-slate-800 hover:border-cyan-500/40 transition-all duration-200 shadow-sm hover:shadow-md"
              >
                <CardHeader className="space-y-3 pb-3">
                  <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-cyan-500/10 border border-cyan-500/30">
                    {agent.icon}
                  </div>
                  <div>
                    <CardTitle className="text-base font-bold text-slate-900 dark:text-slate-100">
                      {agent.name}
                    </CardTitle>
                    <p className="text-xs font-semibold text-cyan-600 dark:text-cyan-400 mt-0.5">
                      {agent.tagline}
                    </p>
                  </div>
                </CardHeader>
                <CardContent>
                  <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                    {agent.description}
                  </p>
                </CardContent>
              </Card>
            ))}
          </div>
        </section>

        {/* ── Capabilities Highlight ───────────────────────────────────── */}
        <section className="rounded-2xl border border-slate-200 bg-white/60 p-8 sm:p-12 dark:border-slate-800 dark:bg-slate-900/60 mb-16">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="space-y-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-500/10 text-cyan-500">
                <Zap size={22} />
              </div>
              <h3 className="text-lg font-bold text-slate-900 dark:text-slate-100">
                Zero Heuristic Lag
              </h3>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                Rules compile synchronously on ingest. Suspicious network bursts or spearphishing headers are scored in under 500 milliseconds.
              </p>
            </div>

            <div className="space-y-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-500">
                <Lock size={22} />
              </div>
              <h3 className="text-lg font-bold text-slate-900 dark:text-slate-100">
                Role-Isolated Workspaces
              </h3>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                Backend-enforced RBAC ensures individual personal logs, analyst evidence lockers, and enterprise security rooms remain strictly segregated.
              </p>
            </div>

            <div className="space-y-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-500/10 text-indigo-500">
                <Cpu size={22} />
              </div>
              <h3 className="text-lg font-bold text-slate-900 dark:text-slate-100">
                Cross-Platform Telemetry
              </h3>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                Lightweight collectors stream telemetry across Windows, Linux, and macOS endpoints with tamper-resistant cryptographic heartbeat authentication.
              </p>
            </div>
          </div>
        </section>

        {/* ── Bottom CTA ──────────────────────────────────────────────── */}
        <div className="text-center py-8">
          <h2 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100 mb-3">
            Ready to secure your digital infrastructure?
          </h2>
          <p className="text-sm text-slate-600 dark:text-slate-400 max-w-xl mx-auto mb-6">
            Join individuals, security analysts, and enterprises using CyberGuard AI to monitor and protect against modern cyber threats.
          </p>
          <Button
            size="lg"
            variant="primary"
            onClick={() => navigate("/select-account")}
            className="text-sm font-bold shadow-md shadow-cyan-500/20"
          >
            Select Your Account Type <ArrowRight size={16} className="ml-1.5" />
          </Button>
        </div>
      </main>

      <PublicFooter />
    </div>
  );
}
