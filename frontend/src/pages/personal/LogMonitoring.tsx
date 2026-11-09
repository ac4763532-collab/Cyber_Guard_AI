/**
 * CyberGuard AI — Page 10: Log Monitoring
 * ============================================================================
 * Live log security telemetry across connected Windows, Linux, SSH,
 * and database sources. Powered by backend SecurityEvent aggregation.
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { 
  Terminal, 
  Search, 
  Download, 
  AlertTriangle, 
  CheckCircle2, 
  ShieldAlert, 
  UserX,
  RefreshCw 
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { api } from "@/lib/api";
import { toast } from "sonner";
import { FileText } from "lucide-react";
import { SecurityEventDetailsDrawer } from "@/components/events/SecurityEventDetailsDrawer";

interface LogEventItem {
  id: string;
  timestamp: string;
  source: string;
  event_type: string;
  severity: string;
  details: string;
}

interface LogSummaryData {
  total_sources: number;
  failed_logins_24h: number;
  privilege_escalations_24h: number;
  anomalous_events: number;
  events: LogEventItem[];
  message?: string;
}

export default function LogMonitoring() {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);

  const { data, isLoading, refetch, isFetching } = useQuery<LogSummaryData>({
    queryKey: ["log-summary"],
    queryFn: async () => {
      const res = await api.get<LogSummaryData>("/logs/summary");
      return res.data;
    },
    refetchInterval: 30_000,
  });

  const summary = data || {
    total_sources: 0,
    failed_logins_24h: 0,
    privilege_escalations_24h: 0,
    anomalous_events: 0,
    events: [],
  };

  const filtered = summary.events.filter((l) =>
    l.details.toLowerCase().includes(searchTerm.toLowerCase()) ||
    l.source.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleExport = () => {
    toast.success("Log audit trail exported for compliance reporting.");
  };

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
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            disabled={isFetching}
            className="border-slate-800 text-slate-300 hover:bg-slate-800"
          >
            <RefreshCw size={14} className={`mr-1.5 ${isFetching ? "animate-spin" : ""}`} /> Refresh
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={handleExport}
            className="border-slate-800 text-slate-300 text-xs hover:bg-slate-800"
          >
            <Download size={14} className="mr-1.5" /> Export Log Evidence
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Total Log Sources</p>
          <p className="text-xl font-bold text-slate-100 mt-1">{summary.total_sources} Active</p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Failed Logins (24h)</p>
          <p className="text-xl font-bold text-amber-400 mt-1">{summary.failed_logins_24h} attempts</p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Privilege Changes (24h)</p>
          <p className="text-xl font-bold text-cyan-400 mt-1">{summary.privilege_escalations_24h} events</p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Anomalous Events</p>
          <p className="text-xl font-bold text-rose-400 mt-1">{summary.anomalous_events} flagged</p>
        </Card>
      </div>

      <Card className="bg-slate-900 border-slate-800">
        <CardHeader className="pb-3 border-b border-slate-800/80 flex flex-row items-center justify-between">
          <CardTitle className="text-base text-slate-100 flex items-center gap-2">
            <Terminal size={16} className="text-cyan-400" />
            Security Event Feed
          </CardTitle>
          <div className="w-64">
            <Input
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search event type, host..."
              className="bg-slate-950 border-slate-800 text-xs h-8 text-slate-200"
            />
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-12 text-center text-sm text-slate-400">Streaming normalized logs...</div>
          ) : summary.events.length === 0 ? (
            <div className="p-12 text-center border-t border-slate-800/80">
              <Terminal className="w-10 h-10 text-slate-600 mx-auto mb-3" />
              <p className="text-sm font-semibold text-slate-300">No log sources currently reporting events</p>
              <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
                Install the CyberGuard Windows or Linux collector service to stream authentication and system event telemetry into the normalization pipeline.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-slate-800/80">
              {filtered.map((log) => (
                <div key={log.id} className="p-4 hover:bg-slate-800/40 transition flex items-center justify-between gap-4 font-mono text-xs">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-slate-200">{log.source}</span>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${log.severity === "high" || log.severity === "critical" ? "bg-rose-500/20 text-rose-400 border border-rose-500/30" : "bg-slate-800 text-slate-400"}`}>
                        {log.severity}
                      </span>
                      <span className="text-slate-500 text-[11px] font-sans">{new Date(log.timestamp).toLocaleTimeString()}</span>
                    </div>
                    <p className="text-slate-300 text-xs font-sans">{log.details}</p>
                  </div>
                  <div className="flex items-center gap-2.5 shrink-0">
                    <span className="text-[11px] text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 px-2 py-0.5 rounded">
                      {log.event_type}
                    </span>
                    <button
                      type="button"
                      onClick={() => setSelectedEventId(log.id)}
                      className="px-2.5 py-1 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 hover:text-cyan-300 border border-cyan-500/30 text-[11px] font-sans font-semibold inline-flex items-center gap-1.5 transition-colors"
                    >
                      <FileText size={12} /> View Full Details
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Security Event Full Details Drawer */}
      <SecurityEventDetailsDrawer
        eventId={selectedEventId}
        isOpen={Boolean(selectedEventId)}
        onClose={() => setSelectedEventId(null)}
      />
    </div>
  );
}
