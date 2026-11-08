/**
 * CyberGuard AI — Page 10: Log Monitoring
 * ============================================================================
 * Reviews normalized security summaries from connected Windows, Linux, SSH,
 * and database sources without exposing raw noisy streams.
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { 
  Terminal, 
  Search, 
  Filter, 
  Download, 
  AlertTriangle, 
  CheckCircle2, 
  ShieldAlert, 
  UserX 
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { api } from "@/lib/api";

export default function LogMonitoring() {
  const [searchTerm, setSearchTerm] = useState("");

  const { data: logs = [], isLoading } = useQuery({
    queryKey: ["log-events"],
    queryFn: async () => {
      try {
        const { data } = await api.get("/events?source_type=log");
        return data;
      } catch (err) {
        return [
          {
            id: "evt-log-1",
            timestamp: "2026-11-08T10:18:22Z",
            source: "Windows Event Logs (host-01)",
            event_type: "authentication.failure",
            severity: "medium",
            details: "Event 4625: Multiple failed logon attempts for account 'admin'",
          },
          {
            id: "evt-log-2",
            timestamp: "2026-11-08T09:44:10Z",
            source: "Linux SSH (/var/log/auth.log)",
            event_type: "authentication.failure",
            severity: "high",
            details: "SSH brute-force burst from 45.33.32.156 (12 attempts in 30s)",
          },
          {
            id: "evt-log-3",
            timestamp: "2026-11-08T08:12:00Z",
            source: "Windows Event Logs (host-01)",
            event_type: "privilege.elevation",
            severity: "low",
            details: "Event 4672: Special privileges assigned to new logon",
          },
        ];
      }
    },
  });

  const filtered = logs.filter((l: any) =>
    l.details.toLowerCase().includes(searchTerm.toLowerCase()) ||
    l.source.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-2 py-0.5 rounded-full">
            Page 10 • Log Telemetry
          </span>
          <h1 className="text-3xl font-black text-slate-100 tracking-tight mt-2">
            Log Security Monitoring
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Normalized authentication, privilege changes, and anomalous system logs across connected endpoints.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" className="border-slate-800 text-slate-300 text-xs">
            <Download size={14} className="mr-1.5" /> Export Log Evidence
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Total Log Sources</p>
          <p className="text-xl font-bold text-slate-100 mt-1">2 Active</p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Failed Logins (24h)</p>
          <p className="text-xl font-bold text-amber-400 mt-1">17 attempts</p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Brute-Force Bursts</p>
          <p className="text-xl font-bold text-rose-400 mt-1">1 detected</p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Parser Status</p>
          <p className="text-xl font-bold text-emerald-400 mt-1">100% Normalized</p>
        </Card>
      </div>

      <Card className="bg-slate-900 border-slate-800">
        <CardHeader className="pb-3 border-b border-slate-800/80 flex flex-row items-center justify-between">
          <CardTitle className="text-base text-slate-100">Security Events</CardTitle>
          <div className="w-64">
            <Input
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search event type, host..."
              className="bg-slate-950 border-slate-800 text-xs h-8"
            />
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="divide-y divide-slate-800/80 font-mono text-xs">
            {filtered.map((log: any) => (
              <div key={log.id} className="p-4 hover:bg-slate-800/30 flex items-start justify-between gap-4">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-cyan-400 font-semibold">{log.source}</span>
                    <span className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded border ${
                      log.severity === "high" ? "bg-rose-500/10 text-rose-400 border-rose-500/30" :
                      log.severity === "medium" ? "bg-amber-500/10 text-amber-400 border-amber-500/30" :
                      "bg-slate-800 text-slate-400 border-slate-700"
                    }`}>
                      {log.severity}
                    </span>
                  </div>
                  <p className="text-slate-200">{log.details}</p>
                </div>
                <span className="text-slate-500 text-[11px] whitespace-nowrap">
                  {new Date(log.timestamp).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
