/**
 * CyberGuard AI — Page 25: Analyst Operations Center (Dashboard)
 * ============================================================================
 * Central dashboard for verified cybersecurity analysts: active assigned cases,
 * new available incident response requests, evidence under triage, and reports.
 */

import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { 
  Briefcase, 
  FolderOpen, 
  Database, 
  FileText, 
  Clock, 
  CheckCircle, 
  AlertTriangle, 
  ArrowRight,
  TrendingUp,
  ShieldAlert
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { useAuth } from "@/auth/AuthProvider";

export default function AnalystDashboard() {
  const { user } = useAuth();
  const navigate = useNavigate();

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      
      {/* ── Header ───────────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded-full">
            Page 25 • Analyst Portal
          </span>
          <h1 className="text-3xl font-black text-slate-100 tracking-tight mt-2">
            Analyst Operations Center
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Prioritize assigned investigations, examine verified forensic evidence, and submit incident reports.
          </p>
        </div>

        <div className="flex gap-3">
          <Button
            onClick={() => navigate("/analyst/available-cases")}
            className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs"
          >
            <FolderOpen size={14} className="mr-1.5" /> Browse Available Cases
          </Button>
        </div>
      </div>

      {/* ── KPI Cards ────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-slate-900 border-slate-800 p-5">
          <p className="text-xs font-semibold text-slate-400">Assigned Active Cases</p>
          <p className="text-2xl font-black text-slate-100 mt-1">3 Cases</p>
          <span className="text-[11px] text-emerald-400 mt-2 block">1 High-Priority</span>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-5">
          <p className="text-xs font-semibold text-slate-400">Evidence Vault Items</p>
          <p className="text-2xl font-black text-cyan-400 mt-1">14 Artifacts</p>
          <span className="text-[11px] text-slate-400 mt-2 block">SHA-256 Verified</span>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-5">
          <p className="text-xs font-semibold text-slate-400">Pending Reports</p>
          <p className="text-2xl font-black text-amber-400 mt-1">2 Drafts</p>
          <span className="text-[11px] text-slate-400 mt-2 block">Due this week</span>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-5">
          <p className="text-xs font-semibold text-slate-400">Available Balance</p>
          <p className="text-2xl font-black text-slate-100 mt-1">$2,450.00</p>
          <span className="text-[11px] text-emerald-400 mt-2 block">Paid automatically</span>
        </Card>
      </div>

      {/* ── Active Cases Table ───────────────────────────────────────── */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Briefcase size={18} className="text-emerald-400" />
            My Priority Assigned Cases
          </h2>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => navigate("/analyst/cases")}
            className="text-xs text-emerald-400 hover:bg-emerald-500/10"
          >
            View All Cases <ArrowRight size={14} className="ml-1" />
          </Button>
        </div>

        <div className="space-y-3">
          <Card className="bg-slate-900 border-slate-800 hover:border-emerald-500/40 transition cursor-pointer" onClick={() => navigate("/analyst/cases/CASE-2026-0042")}>
            <CardContent className="p-5 flex items-center justify-between">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-cyan-400">CASE-2026-0042</span>
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30 uppercase">
                    Urgent
                  </span>
                </div>
                <h3 className="font-bold text-slate-100 text-sm">Targeted Executive Spearphishing Campaign Investigation</h3>
                <p className="text-xs text-slate-400">Client: riya-user-000184 • 4 attachments, 2 malicious URLs identified</p>
              </div>

              <div className="flex items-center gap-3">
                <Button size="sm" className="bg-slate-800 hover:bg-emerald-500 hover:text-slate-950 text-xs font-semibold">
                  Open Workbench
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

    </div>
  );
}
