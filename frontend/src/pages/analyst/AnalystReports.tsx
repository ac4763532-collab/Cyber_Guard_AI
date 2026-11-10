/**
 * CyberGuard AI — Page 32: Analyst Reports
 * ============================================================================
 * Register of case reports drafted, submitted, and approved by the analyst.
 */

import { useState } from "react";
import { FileText, Download, Share2, CheckCircle, Clock } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { toast } from "sonner";

export default function AnalystReports() {
  const reports = [
    {
      id: "REP-2026-0042",
      case_id: "CASE-2026-0042",
      title: "Executive Spearphishing Attack Forensics & Remediation Advisory",
      author: "Assigned Analyst",
      status: "submitted",
      date: "2026-11-08",
      version: "v1.0",
      findings_count: 3,
    },
  ];

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded-full">
            Page 32 • Formal Reports
          </span>
          <h1 className="text-3xl font-black text-slate-100 tracking-tight mt-2">
            Investigation Reports
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Formal forensic findings, timeline reconstructs, and executive security deliverables.
          </p>
        </div>
      </div>

      <div className="space-y-4">
        {reports.map((r) => (
          <Card key={r.id} className="bg-slate-900 border-slate-800 hover:border-emerald-500/40 transition">
            <CardContent className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-cyan-400">{r.id}</span>
                  <span className="font-mono text-xs text-slate-400">({r.case_id})</span>
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                    {r.version} • {r.status.toUpperCase()}
                  </span>
                </div>
                <h3 className="font-bold text-slate-100 text-base">{r.title}</h3>
                <p className="text-xs text-slate-400">
                  {r.findings_count} critical findings documented • Generated {r.date}
                </p>
              </div>

              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  onClick={() => toast.success("Downloading cryptographic PDF report...")}
                  className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs"
                >
                  <Download size={14} className="mr-1.5" /> Download PDF
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
