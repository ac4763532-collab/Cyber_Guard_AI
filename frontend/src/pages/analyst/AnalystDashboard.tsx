/**
 * CyberGuard AI — Page 25: Analyst Operations Center (Dashboard)
 * ============================================================================
 * Central dashboard for verified cybersecurity analysts: active assigned cases,
 * new available incident response requests, evidence under triage, and reports.
 * Connected to live backend metrics and cases.
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
  ShieldAlert,
  Inbox
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Spinner } from "@/components/ui/Spinner";
import { api } from "@/lib/api";
import { formatRelativeTime } from "@/lib/utils";

interface AnalystCaseItem {
  id: string;
  case_number: string;
  title: string;
  severity: string;
  status: string;
  created_at: string;
}

interface AnalystDashboardData {
  active_cases: number;
  available_cases: number;
  evidence_count: number;
  pending_reports: number;
  balance_usd: number;
  recent_cases: AnalystCaseItem[];
}

export default function AnalystDashboard() {
  const navigate = useNavigate();

  const { data, isLoading } = useQuery<AnalystDashboardData>({
    queryKey: ["analyst-dashboard"],
    queryFn: async () => {
      const { data } = await api.get<AnalystDashboardData>("/dashboard/analyst");
      return data;
    },
    refetchInterval: 12000,
  });

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
            <FolderOpen size={14} className="mr-1.5" /> Browse Available Cases ({data?.available_cases ?? 0})
          </Button>
        </div>
      </div>

      {/* ── KPI Cards ────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-slate-900 border-slate-800 p-5">
          <p className="text-xs font-semibold text-slate-400">Assigned Active Cases</p>
          <p className="text-2xl font-black text-slate-100 mt-1">
            {isLoading ? "..." : `${data?.active_cases ?? 0} Cases`}
          </p>
          <span className="text-[11px] text-emerald-400 mt-2 block">
            {data?.active_cases ? "Active investigations" : "No open assignments"}
          </span>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-5">
          <p className="text-xs font-semibold text-slate-400">Evidence Vault Items</p>
          <p className="text-2xl font-black text-cyan-400 mt-1">
            {isLoading ? "..." : `${data?.evidence_count ?? 0} Artifacts`}
          </p>
          <span className="text-[11px] text-slate-400 mt-2 block">SHA-256 Verified</span>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-5">
          <p className="text-xs font-semibold text-slate-400">Pending Reports</p>
          <p className="text-2xl font-black text-amber-400 mt-1">
            {isLoading ? "..." : `${data?.pending_reports ?? 0} Pending`}
          </p>
          <span className="text-[11px] text-slate-400 mt-2 block">Case deliverables</span>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-5">
          <p className="text-xs font-semibold text-slate-400">Available Balance</p>
          <p className="text-2xl font-black text-slate-100 mt-1">
            {isLoading ? "..." : `$${(data?.balance_usd ?? 0).toFixed(2)}`}
          </p>
          <span className="text-[11px] text-emerald-400 mt-2 block">Settled payouts</span>
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

        {isLoading ? (
          <div className="p-8 text-center"><Spinner label="Loading priority cases..." /></div>
        ) : (!data?.recent_cases || data.recent_cases.length === 0) ? (
          <Card className="bg-slate-900 border-slate-800">
            <CardContent className="p-8 text-center text-slate-400">
              <Inbox size={40} className="mx-auto text-slate-600 mb-2" />
              <p className="font-semibold text-slate-300">No active assigned cases</p>
              <p className="text-xs mt-1 text-slate-500 max-w-sm mx-auto">
                You do not have any pending assigned cases at this time. Browse available cases from the marketplace to take on an investigation.
              </p>
              <Button
                size="sm"
                onClick={() => navigate("/analyst/available-cases")}
                className="mt-4 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs"
              >
                Browse Marketplace
              </Button>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-3">
            {data.recent_cases.map((c) => (
              <Card 
                key={c.id} 
                className="bg-slate-900 border-slate-800 hover:border-emerald-500/40 transition cursor-pointer" 
                onClick={() => navigate(`/analyst/cases/${c.id}`)}
              >
                <CardContent className="p-5 flex items-center justify-between">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-cyan-400">{c.case_number}</span>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase border ${
                        c.severity === "critical" || c.severity === "high"
                          ? "bg-rose-500/20 text-rose-400 border-rose-500/30"
                          : "bg-amber-500/20 text-amber-400 border-amber-500/30"
                      }`}>
                        {c.severity}
                      </span>
                      <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        {c.status}
                      </span>
                    </div>
                    <h3 className="font-bold text-slate-100 text-sm">{c.title}</h3>
                    <p className="text-xs text-slate-400 font-mono">
                      Opened {formatRelativeTime(c.created_at)}
                    </p>
                  </div>

                  <div className="flex items-center gap-3">
                    <Button
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate(`/analyst/cases/${c.id}`);
                      }}
                      className="bg-slate-800 hover:bg-emerald-500 hover:text-slate-950 text-xs font-semibold"
                    >
                      Open Workbench
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>

    </div>
  );
}
