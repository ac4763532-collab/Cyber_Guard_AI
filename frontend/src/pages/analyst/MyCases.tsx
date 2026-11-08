/**
 * CyberGuard AI — Page 26: My Cases (Analyst)
 * ============================================================================
 * Lists cases explicitly assigned to the verified analyst. Analysts cannot
 * access cases not assigned to them.
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Briefcase, Search, ArrowRight, ShieldAlert, Clock, CheckCircle, Inbox } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Spinner } from "@/components/ui/Spinner";
import { api } from "@/lib/api";
import { formatRelativeTime } from "@/lib/utils";

interface CaseItem {
  id: string;
  case_number: string;
  title: string;
  status: string;
  severity: string;
  assigned_to_user_id: string | null;
  created_at: string;
}

export default function MyCases() {
  const navigate = useNavigate();
  const [searchTerm, setSearchTerm] = useState("");

  const { data, isLoading } = useQuery<{ items: CaseItem[]; total: number }>({
    queryKey: ["analyst-my-cases"],
    queryFn: async () => {
      const { data } = await api.get<{ items: CaseItem[]; total: number }>("/cases", {
        params: { page: 1, page_size: 50 },
      });
      return data;
    },
  });

  const filtered = (data?.items || []).filter((c) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      c.case_number.toLowerCase().includes(term) ||
      c.title.toLowerCase().includes(term) ||
      c.status.toLowerCase().includes(term) ||
      c.severity.toLowerCase().includes(term)
    );
  });

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded-full">
            Page 26 • Analyst Cases
          </span>
          <h1 className="text-3xl font-black text-slate-100 tracking-tight mt-2">
            My Assigned Cases
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Work exclusively on active security investigations assigned to your verified analyst identity.
          </p>
        </div>
      </div>

      <div className="w-full max-w-md">
        <Input
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Search case ID, title, status, severity..."
          className="bg-slate-900 border-slate-800 text-xs"
        />
      </div>

      {isLoading ? (
        <div className="p-12 text-center">
          <Spinner label="Loading assigned investigations..." />
        </div>
      ) : filtered.length === 0 ? (
        <Card className="bg-slate-900 border-slate-800">
          <CardContent className="p-12 text-center text-slate-400">
            <Inbox size={48} className="mx-auto text-slate-600 mb-3" />
            <h3 className="text-base font-bold text-slate-200">No assigned cases found</h3>
            <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
              {searchTerm 
                ? "No cases match your search query." 
                : "You do not currently have any assigned cases. Visit the Available Cases marketplace to review and accept incoming requests."}
            </p>
            <Button
              size="sm"
              onClick={() => navigate("/analyst/available-cases")}
              className="mt-4 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs"
            >
              Browse Available Cases
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {filtered.map((c) => (
            <Card key={c.id} className="bg-slate-900 border-slate-800 hover:border-emerald-500/50 transition">
              <CardContent className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-cyan-400">{c.case_number}</span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase border ${
                      c.severity === "critical" || c.severity === "urgent"
                        ? "bg-rose-500/20 text-rose-400 border-rose-500/30" 
                        : "bg-amber-500/20 text-amber-400 border-amber-500/30"
                    }`}>
                      {c.severity} Priority
                    </span>
                    <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                      {c.status}
                    </span>
                  </div>
                  <h3 className="font-bold text-slate-100 text-base">{c.title}</h3>
                  <p className="text-xs text-slate-400 font-mono">
                    Opened {formatRelativeTime(c.created_at)}
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    onClick={() => navigate(`/analyst/cases/${c.id}`)}
                    className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs"
                  >
                    Enter Investigation <ArrowRight size={14} className="ml-1" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
