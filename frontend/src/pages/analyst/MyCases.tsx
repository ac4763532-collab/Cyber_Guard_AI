/**
 * CyberGuard AI — Page 26: My Cases (Analyst)
 * ============================================================================
 * Lists cases explicitly assigned to the verified analyst. Analysts cannot
 * access cases not assigned to them.
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Briefcase, Search, ArrowRight, ShieldAlert, Clock, CheckCircle } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";

export default function MyCases() {
  const navigate = useNavigate();
  const [searchTerm, setSearchTerm] = useState("");

  const cases = [
    {
      id: "CASE-2026-0042",
      title: "Targeted Executive Spearphishing Campaign Investigation",
      client: "riya-user-000184",
      priority: "high",
      status: "investigating",
      due: "In 2 days",
      evidence_count: 4,
    },
    {
      id: "CASE-2026-0043",
      title: "Anomalous Endpoint C2 Beaconing Triage",
      client: "acme-organizer-000012",
      priority: "urgent",
      status: "assigned",
      due: "Today",
      evidence_count: 6,
    },
  ];

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
          placeholder="Search case ID, title, requester..."
          className="bg-slate-900 border-slate-800 text-xs"
        />
      </div>

      <div className="space-y-4">
        {cases.map((c) => (
          <Card key={c.id} className="bg-slate-900 border-slate-800 hover:border-emerald-500/50 transition">
            <CardContent className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-cyan-400">{c.id}</span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase border ${
                    c.priority === "urgent" ? "bg-rose-500/20 text-rose-400 border-rose-500/30" : "bg-amber-500/20 text-amber-400 border-amber-500/30"
                  }`}>
                    {c.priority} Priority
                  </span>
                  <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                    {c.status}
                  </span>
                </div>
                <h3 className="font-bold text-slate-100 text-base">{c.title}</h3>
                <p className="text-xs text-slate-400">
                  Client ID: <span className="font-mono text-cyan-300">{c.client}</span> • {c.evidence_count} evidence items linked • Due: {c.due}
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
    </div>
  );
}
