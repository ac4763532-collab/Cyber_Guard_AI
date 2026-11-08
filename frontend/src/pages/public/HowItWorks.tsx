/**
 * CyberGuard AI — How It Works Page (/how-it-works)
 * ============================================================================
 * Step-by-step breakdown of the 5-stage threat ingestion, detection,
 * correlation, investigation, and response pipeline.
 */

import { useNavigate } from "react-router-dom";
import { 
  Radio, 
  Database, 
  Cpu, 
  Network, 
  ShieldCheck, 
  ArrowRight,
  CheckCircle,
  ExternalLink,
  Lock,
  Layers
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import PublicNavbar from "@/components/public/PublicNavbar";
import PublicFooter from "@/components/public/PublicFooter";

const stages = [
  {
    step: "01",
    title: "Connect & Ingest",
    subtitle: "Lightweight Telemetry Collectors",
    icon: <Radio className="w-6 h-6 text-cyan-400" />,
    description: "Enroll endpoints, cloud workspaces, or email integrations with zero-friction collectors. Telemetry is encrypted via TLS 1.3 before leaving the boundary.",
    details: [
      "Cross-platform support: Windows, Linux, macOS",
      "Cryptographic source tokens for tamper-proof heartbeat verification",
      "Zero invasive kernel hooking or system overhead"
    ]
  },
  {
    step: "02",
    title: "Collect & Normalize",
    subtitle: "Unified Schema Mapping",
    icon: <Database className="w-6 h-6 text-cyan-400" />,
    description: "Heterogeneous event formats are converted into a standardized JSON payload structure with normalized event timestamps, IP identifiers, and MITRE metadata.",
    details: [
      "Strict schema validation on every inbound security event",
      "Deduplication and rate-limited queueing for high throughput",
      "Persistent audit trail guaranteeing forensic defensibility"
    ]
  },
  {
    step: "03",
    title: "Detect & Analyze",
    subtitle: "Specialized AI Agents Execution",
    icon: <Cpu className="w-6 h-6 text-cyan-400" />,
    description: "Eight specialist AI agents inspect specific telemetry categories in parallel: EML headers, authentication anomalies, suspicious DNS beacons, and process forks.",
    details: [
      "Real-time scoring against external threat intelligence (VirusTotal, AbuseIPDB)",
      "High-confidence alert generation with contextual rationale",
      "Continuous confidence updates as new telemetry arrives"
    ]
  },
  {
    step: "04",
    title: "Correlate & Cluster",
    subtitle: "Multi-Source Attack Graphing",
    icon: <Network className="w-6 h-6 text-cyan-400" />,
    description: "Individual findings are bridged into incident clusters. If a phishing click is followed by an anomalous SSH login, the system links them into a single incident timeline.",
    details: [
      "Eliminates duplicate alerts and notification overload",
      "Automated MITRE ATT&CK tactic and technique tagging",
      "Visual attack chain reconstruction"
    ]
  },
  {
    step: "05",
    title: "Respond & Resolve",
    subtitle: "Analyst Collaboration & War Rooms",
    icon: <ShieldCheck className="w-6 h-6 text-cyan-400" />,
    description: "Organizers invite verified security analysts to private war rooms. Analysts review verified evidence, recommend playbooks, and draft cryptographically verifiable reports.",
    details: [
      "Direct join security rooms with encrypted passcodes",
      "Case management with chain-of-custody evidence vault",
      "Exportable executive and compliance summary reports"
    ]
  }
];

export default function HowItWorks() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100 flex flex-col font-sans">
      <PublicNavbar />

      <main className="flex-1 mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-12">
        {/* Header */}
        <div className="text-center max-w-3xl mx-auto space-y-4 mb-16">
          <span className="text-xs font-bold uppercase tracking-wider text-cyan-600 dark:text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-3 py-1 rounded-full">
            Pipeline Architecture
          </span>
          <h1 className="text-3xl sm:text-5xl font-black tracking-tight text-slate-900 dark:text-slate-100">
            How CyberGuard AI Secures Your Fleet
          </h1>
          <p className="text-base sm:text-lg text-slate-600 dark:text-slate-400">
            From endpoint sensor telemetry to multi-agent correlation and analyst resolution: explore the 5 stages of our autonomous cybersecurity engine.
          </p>
        </div>

        {/* 5-Stage Pipeline */}
        <div className="space-y-8 mb-20 max-w-4xl mx-auto">
          {stages.map((stage, idx) => (
            <Card
              key={stage.step}
              className="bg-white/80 dark:bg-slate-900/80 border-slate-200 dark:border-slate-800 p-6 sm:p-8 hover:border-cyan-500/40 transition-all duration-200"
            >
              <div className="flex flex-col sm:flex-row sm:items-start gap-6">
                <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-500 font-mono text-xl font-black">
                  {stage.step}
                </div>

                <div className="flex-1 space-y-3">
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <div>
                      <h2 className="text-xl font-bold text-slate-900 dark:text-slate-100">
                        {stage.title}
                      </h2>
                      <p className="text-xs font-semibold text-cyan-600 dark:text-cyan-400">
                        {stage.subtitle}
                      </p>
                    </div>
                    <div className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800">
                      {stage.icon}
                    </div>
                  </div>

                  <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
                    {stage.description}
                  </p>

                  <ul className="space-y-2 pt-2 border-t border-slate-100 dark:border-slate-800/80">
                    {stage.details.map((item, i) => (
                      <li key={i} className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
                        <CheckCircle size={14} className="text-emerald-500 shrink-0" />
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </Card>
          ))}
        </div>

        {/* CTA */}
        <div className="rounded-2xl border border-slate-200 bg-white/70 p-8 sm:p-12 text-center dark:border-slate-800 dark:bg-slate-900/70 max-w-4xl mx-auto">
          <h2 className="text-2xl font-bold text-slate-900 dark:text-slate-100 mb-2">
            Experience the automated pipeline in action
          </h2>
          <p className="text-sm text-slate-600 dark:text-slate-400 max-w-md mx-auto mb-6">
            Configure your account in under 2 minutes and explore our agent findings live.
          </p>
          <div className="flex flex-wrap items-center justify-center gap-4">
            <Button
              size="lg"
              variant="primary"
              onClick={() => navigate("/select-account")}
              className="text-sm font-bold"
            >
              Get Started Now <ArrowRight size={16} className="ml-1.5" />
            </Button>
            <Button
              size="lg"
              variant="outline"
              onClick={() => navigate("/features")}
              className="text-sm font-semibold"
            >
              Browse AI Agents
            </Button>
          </div>
        </div>
      </main>

      <PublicFooter />
    </div>
  );
}
