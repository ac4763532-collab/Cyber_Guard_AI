/**
 * CyberGuard AI — Page 27: Available Cases
 * ============================================================================
 * Browse unassigned case opportunities. Restricted forensic evidence remains
 * hidden until explicit assignment and customer authorization.
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { FolderOpen, Search, Shield, DollarSign, ArrowRight, Lock } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { toast } from "sonner";

export default function AvailableCases() {
  const navigate = useNavigate();
  const [searchTerm, setSearchTerm] = useState("");

  const opportunities = [
    {
      id: "OPP-0089",
      title: "Suspicious PowerShell Invocations & Memory Artifacts",
      category: "Endpoint Forensics",
      budget: "$350 Fixed",
      scope: "Windows 11 telemetry and process execution logs",
      posted: "1 hour ago",
      required_skills: ["Volatility", "Sysmon", "PowerShell De-obfuscation"],
    },
    {
      id: "OPP-0090",
      title: "Ransomware Delivery Pre-cursor Investigation",
      category: "Threat Hunting",
      budget: "$500 Fixed",
      scope: "Firewall flows and anomalous SMB traffic review",
      posted: "3 hours ago",
      required_skills: ["Network Forensics", "Wireshark", "MITRE ATT&CK"],
    },
  ];

  const handleApply = (oppId: string) => {
    toast.success(`Application submitted for case ${oppId}. Assigned after customer review!`);
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded-full">
            Page 27 • Case Opportunities
          </span>
          <h1 className="text-3xl font-black text-slate-100 tracking-tight mt-2">
            Available Security Cases
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Apply for investigation requests posted by individuals and enterprise organizations.
          </p>
        </div>
      </div>

      <div className="space-y-4">
        {opportunities.map((opp) => (
          <Card key={opp.id} className="bg-slate-900 border-slate-800 hover:border-emerald-500/40 transition">
            <CardContent className="p-6 flex flex-col md:flex-row md:items-center justify-between gap-5">
              <div className="space-y-2 max-w-2xl">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-cyan-400">{opp.id}</span>
                  <span className="text-xs font-semibold px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    {opp.category}
                  </span>
                  <span className="text-xs font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded">
                    {opp.budget}
                  </span>
                </div>
                <h3 className="font-bold text-slate-100 text-base">{opp.title}</h3>
                <p className="text-xs text-slate-400">{opp.scope}</p>
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {opp.required_skills.map((s) => (
                    <span key={s} className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800">
                      {s}
                    </span>
                  ))}
                </div>
              </div>

              <div className="flex flex-col gap-2 shrink-0">
                <Button
                  size="sm"
                  onClick={() => handleApply(opp.id)}
                  className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs"
                >
                  Accept & Apply
                </Button>
                <span className="text-[11px] text-slate-500 flex items-center justify-center gap-1">
                  <Lock size={12} /> Evidence gated
                </span>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
