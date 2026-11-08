/**
 * CyberGuard AI — Page 11: Network Security
 * ============================================================================
 * Reviews network flow telemetry, active sensors, suspicious outbound flows,
 * port scan attempts, and malicious IP correlation from PostgreSQL records.
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { 
  Wifi, 
  Globe, 
  ShieldAlert, 
  Radio, 
  Activity, 
  CheckCircle2, 
  AlertOctagon,
  RefreshCw 
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { api } from "@/lib/api";
import { toast } from "sonner";

interface NetworkSummary {
  sensors: number;
  flows_count: number;
  suspicious: number;
  active_threat_feeds: string[];
  message?: string;
}

interface FlowRecord {
  id: string;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  source_port?: number;
  destination_port?: number;
  protocol: string;
  severity: string;
  action: string;
  rule?: string;
  threat_intel_match: boolean;
}

export default function NetworkSecurity() {
  const { data: summary, isLoading: isSummaryLoading, refetch, isFetching } = useQuery<NetworkSummary>({
    queryKey: ["network-summary"],
    queryFn: async () => {
      const res = await api.get<NetworkSummary>("/network/summary");
      return res.data;
    },
    refetchInterval: 30_000,
  });

  const { data: flows = [], isLoading: isFlowsLoading } = useQuery<FlowRecord[]>({
    queryKey: ["network-flows"],
    queryFn: async () => {
      const res = await api.get<FlowRecord[]>("/network/flows");
      return res.data || [];
    },
    refetchInterval: 30_000,
  });

  const net = summary || {
    sensors: 0,
    flows_count: 0,
    suspicious: 0,
    active_threat_feeds: ["Internal IOC Engine"],
  };

  const handleEnrollSensor = () => {
    toast.info("Register a Network Gateway sensor in the Devices tab under Operating System: Network Sensor.");
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-2 py-0.5 rounded-full">
            Page 11 • Network Telemetry
          </span>
          <h1 className="text-3xl font-black text-slate-100 tracking-tight mt-2">
            Network Security & Flow Inspection
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Sensor telemetry, egress traffic analysis, beaconing detection, and threat intelligence IoC correlation.
          </p>
        </div>

        <div className="flex items-center gap-3">
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
            size="sm"
            onClick={handleEnrollSensor}
            className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
          >
            <Radio size={14} className="mr-1.5" /> Enroll Network Sensor
          </Button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Active Sensors</p>
          <p className="text-xl font-bold text-emerald-400 mt-1">{net.sensors} Connected</p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Flow Records Analyzed</p>
          <p className="text-xl font-bold text-slate-100 mt-1">{net.flows_count.toLocaleString()} Flows</p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Suspicious Connections</p>
          <p className="text-xl font-bold text-rose-400 mt-1">{net.suspicious} Blocked / Flagged</p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Threat Intel Feeds</p>
          <p className="text-xl font-bold text-cyan-400 mt-1">{net.active_threat_feeds.join(" • ")}</p>
        </Card>
      </div>

      {/* Network Flow Inspection */}
      <div className="grid grid-cols-1 gap-5">
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader>
            <CardTitle className="text-base text-slate-100 flex items-center gap-2">
              <Activity size={16} className="text-cyan-400" />
              Observed Network Flows & Telemetry
            </CardTitle>
          </CardHeader>
          <CardContent>
            {isSummaryLoading || isFlowsLoading ? (
              <div className="p-12 text-center text-sm text-slate-400">Polling network sensors...</div>
            ) : flows.length === 0 ? (
              <div className="py-12 text-center border-t border-slate-800/80">
                <Wifi className="w-10 h-10 text-slate-600 mx-auto mb-3" />
                <p className="text-sm font-semibold text-slate-300">No authorized network sensor is connected</p>
                <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
                  Enroll an endpoint sensor or configure firewall / NetFlow telemetry forwarding to begin inspecting live egress traffic and detecting port sweeps.
                </p>
              </div>
            ) : (
              <div className="space-y-3 font-mono text-xs">
                {flows.map((fl) => (
                  <div key={fl.id} className="p-3 bg-slate-950/70 rounded-lg border border-slate-800 flex items-center justify-between">
                    <div>
                      <span className="text-slate-200 font-bold">
                        {fl.source_ip}:{fl.source_port || 0} → {fl.destination_ip}:{fl.destination_port || 0} ({fl.protocol})
                      </span>
                      <p className="text-[11px] text-slate-400 mt-0.5">
                        {fl.rule || `Action: ${fl.action}`} • Timestamp: {new Date(fl.timestamp).toLocaleTimeString()}
                      </p>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${fl.threat_intel_match ? "bg-rose-500/20 text-rose-400 border border-rose-500/30" : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"}`}>
                      {fl.action.toUpperCase()}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
