/**
 * CyberGuard AI — Page 27: Available Cases
 * ============================================================================
 * Browse unassigned case opportunities. Restricted forensic evidence remains
 * hidden until explicit assignment and customer authorization.
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { FolderOpen, Search, Shield, DollarSign, ArrowRight, Lock, Inbox } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Spinner } from "@/components/ui/Spinner";
import { api } from "@/lib/api";
import { formatRelativeTime } from "@/lib/utils";
import { toast } from "sonner";

interface AvailableCase {
  id: string;
  case_number: string;
  title: string;
  status: string;
  severity: string;
  created_at: string;
}

export default function AvailableCases() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [searchTerm, setSearchTerm] = useState("");

  const { data, isLoading } = useQuery<{ items: AvailableCase[]; total: number }>({
    queryKey: ["available-cases"],
    queryFn: async () => {
      const { data } = await api.get<{ items: AvailableCase[]; total: number }>("/cases", {
        params: { page: 1, page_size: 50 },
      });
      return data;
    },
  });

  const acceptMutation = useMutation({
    mutationFn: async (caseId: string) => {
      // Add note or assign analyst
      await api.post(`/cases/${caseId}/notes`, {
        note_type: "investigation",
        content: "Analyst requested assignment and initiated preliminary evidence triage.",
      });
    },
    onSuccess: (_, caseId) => {
      toast.success("Applied to case investigation. Routing to workbench.");
      queryClient.invalidateQueries({ queryKey: ["available-cases"] });
      queryClient.invalidateQueries({ queryKey: ["analyst-my-cases"] });
      navigate(`/analyst/cases/${caseId}`);
    },
    onError: (err: any) => {
      toast.error(err?.message || "Failed to accept case");
    },
  });

  const filtered = (data?.items || []).filter((c) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      c.case_number.toLowerCase().includes(term) ||
      c.title.toLowerCase().includes(term) ||
      c.severity.toLowerCase().includes(term)
    );
  });

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

      <div className="w-full max-w-md">
        <Input
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Filter available opportunities by title, severity, number..."
          className="bg-slate-900 border-slate-800 text-xs"
        />
      </div>

      {isLoading ? (
        <div className="p-12 text-center">
          <Spinner label="Loading available case opportunities..." />
        </div>
      ) : filtered.length === 0 ? (
        <Card className="bg-slate-900 border-slate-800">
          <CardContent className="p-12 text-center text-slate-400">
            <Inbox size={48} className="mx-auto text-slate-600 mb-3" />
            <h3 className="text-base font-bold text-slate-200">No open cases available</h3>
            <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
              All currently posted incidents have been assigned or resolved. New incidents requiring analyst triage will appear here in real-time.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {filtered.map((opp) => (
            <Card key={opp.id} className="bg-slate-900 border-slate-800 hover:border-emerald-500/40 transition">
              <CardContent className="p-6 flex flex-col md:flex-row md:items-center justify-between gap-5">
                <div className="space-y-2 max-w-2xl">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-cyan-400">{opp.case_number}</span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase border ${
                      opp.severity === "critical" || opp.severity === "high"
                        ? "bg-rose-500/20 text-rose-400 border-rose-500/30"
                        : "bg-amber-500/20 text-amber-400 border-amber-500/30"
                    }`}>
                      {opp.severity}
                    </span>
                    <span className="text-xs font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded">
                      Standard Investigation
                    </span>
                  </div>
                  <h3 className="font-bold text-slate-100 text-base">{opp.title}</h3>
                  <p className="text-xs text-slate-400 font-mono">
                    Opened {formatRelativeTime(opp.created_at)} • Status: {opp.status}
                  </p>
                </div>

                <div className="flex flex-col gap-2 shrink-0">
                  <Button
                    size="sm"
                    onClick={() => acceptMutation.mutate(opp.id)}
                    isLoading={acceptMutation.isPending}
                    className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs"
                  >
                    Accept & Investigate
                  </Button>
                  <span className="text-[11px] text-slate-500 flex items-center justify-center gap-1">
                    <Lock size={12} /> Evidence gated
                  </span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
