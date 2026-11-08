/**
 * CyberGuard AI — Page 30: Investigation & Reports Workbench
 * ============================================================================
 * Deep forensic analysis across Email, Log, and Network domains for assigned cases.
 * Generates reproducible, evidence-grounded investigation reports.
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { 
  Microscope, 
  Sparkles, 
  FileText, 
  Mail, 
  Terminal, 
  Wifi, 
  CheckCircle, 
  Send,
  Download
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { toast } from "sonner";

export default function AIInvestigation() {
  const navigate = useNavigate();
  const [activeDomain, setActiveDomain] = useState<"email" | "log" | "network">("email");
  const [isGenerating, setIsGenerating] = useState(false);

  const handleGenerate = () => {
    setIsGenerating(true);
    setTimeout(() => {
      setIsGenerating(false);
      toast.success("Investigation Report v1.0 compiled successfully with evidence citations!");
    }, 1200);
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded-full">
            Page 30 • Investigation Workbench
          </span>
          <h1 className="text-3xl font-black text-slate-100 tracking-tight mt-2">
            Forensic Investigation & Reports Workbench
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Run deterministic forensic analysis and multi-source event correlation for assigned cases.
          </p>
        </div>

        <div className="flex gap-2">
          <Button
            size="sm"
            onClick={handleGenerate}
            disabled={isGenerating}
            className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs"
          >
            <Sparkles size={14} className="mr-1.5" />
            {isGenerating ? "Compiling Report..." : "Generate Case Report"}
          </Button>
        </div>
      </div>

      {/* Domain Switcher */}
      <div className="flex gap-3 border-b border-slate-800 pb-3">
        <button
          onClick={() => setActiveDomain("email")}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition ${
            activeDomain === "email"
              ? "bg-cyan-500/15 text-cyan-400 border border-cyan-500/30"
              : "text-slate-400 hover:bg-slate-800/60"
          }`}
        >
          <Mail size={16} /> Email Forensics
        </button>
        <button
          onClick={() => setActiveDomain("log")}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition ${
            activeDomain === "log"
              ? "bg-cyan-500/15 text-cyan-400 border border-cyan-500/30"
              : "text-slate-400 hover:bg-slate-800/60"
          }`}
        >
          <Terminal size={16} /> Log & System Auth
        </button>
        <button
          onClick={() => setActiveDomain("network")}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition ${
            activeDomain === "network"
              ? "bg-cyan-500/15 text-cyan-400 border border-cyan-500/30"
              : "text-slate-400 hover:bg-slate-800/60"
          }`}
        >
          <Wifi size={16} /> Network Telemetry
        </button>
      </div>

      {/* Analysis Results Preview */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2 bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle className="text-base text-slate-100 flex items-center justify-between">
              <span>Automated Forensic Verdict & Telemetry</span>
              <span className="text-xs font-mono text-cyan-400">Rule Engine v2.4</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-xs text-slate-300 leading-relaxed">
            <div className="p-4 bg-slate-950 rounded-xl border border-rose-500/30 space-y-2">
              <span className="font-bold text-rose-400 text-sm">Critical Finding: Credential Phishing & Malicious C2 Egress</span>
              <p>
                The artifact <span className="font-mono text-cyan-300">phishing_payload_email_raw.eml</span> contained an obfuscated link directing to lookalike infrastructure (<span className="font-mono text-rose-300">185.220.101.5</span>).
              </p>
              <p>
                Correlated with Network Flow: 2 outbound TLS sessions established from endpoint <span className="font-mono text-cyan-300">host-01</span> within 4 minutes of email receipt. Blocked by Gateway Sensor.
              </p>
            </div>

            <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
              <span className="font-bold text-slate-100">MITRE ATT&CK Matrix Mapping</span>
              <ul className="list-disc list-inside space-y-1 text-slate-400">
                <li><span className="font-mono text-cyan-300">T1566.002</span> — Spearphishing Link</li>
                <li><span className="font-mono text-cyan-300">T1071.001</span> — Application Layer Protocol: Web Protocols</li>
                <li><span className="font-mono text-cyan-300">T1078.003</span> — Valid Accounts: Local Accounts (Failed Brute Force)</li>
              </ul>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle className="text-base text-slate-100">Report Deliverable</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-xs">
            <p className="text-slate-400">
              The compiled report includes client executive summary, timeline of observations, raw IoCs, and recommended remediation steps.
            </p>
            <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1 font-mono text-[11px]">
              <p className="text-slate-300">Status: Draft v1.0</p>
              <p className="text-slate-400">Target Case: CASE-2026-0042</p>
              <p className="text-emerald-400">Ready for Customer Review</p>
            </div>

            <Button
              onClick={() => {
                toast.success("Draft submitted to Case Details & Client Inbox");
                navigate("/analyst/reports");
              }}
              className="w-full bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs"
            >
              Submit Report to Client
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
