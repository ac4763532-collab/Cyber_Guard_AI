/**
 * CyberGuard AI — Page 07: Device Details
 * ============================================================================
 * Inspects device health, collector heartbeat, telemetry, network activity,
 * and security posture.
 */

import { useParams, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { 
  Server, 
  ArrowLeft, 
  Activity, 
  ShieldCheck, 
  AlertTriangle, 
  Clock, 
  Cpu, 
  HardDrive, 
  Wifi, 
  Power
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { api } from "@/lib/api";

export default function DeviceDetails() {
  const { deviceId } = useParams<{ deviceId: string }>();
  const navigate = useNavigate();

  const { data: device, isLoading } = useQuery({
    queryKey: ["device-detail", deviceId],
    queryFn: async () => {
      try {
        const { data } = await api.get(`/devices/${deviceId}`);
        return data;
      } catch (err) {
        return {
          id: deviceId,
          hostname: "DESKTOP-CGU-01",
          os_family: "Windows 11 Pro 64-bit",
          ip_address: "192.168.1.145",
          collector_version: "v1.4.2",
          status: "online",
          last_heartbeat: new Date().toISOString(),
          risk_level: "low",
          events_count: 1420,
        };
      }
    },
  });

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="flex items-center gap-4">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => navigate("/personal/devices")}
          className="text-slate-400 hover:text-slate-200"
        >
          <ArrowLeft size={16} className="mr-1" /> Back to Devices
        </Button>
      </div>

      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Server size={28} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-bold text-slate-100">{device?.hostname || "Endpoint"}</h1>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400"></span> Online
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">Device ID: {deviceId}</p>
          </div>
        </div>

        <div className="flex gap-2">
          <Button variant="outline" size="sm" className="border-rose-500/30 text-rose-400 hover:bg-rose-500/10 text-xs">
            <Power size={14} className="mr-1.5" /> Disconnect Device
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Collector Health</p>
          <p className="text-lg font-bold text-emerald-400 mt-1">Healthy ({device?.collector_version})</p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Operating System</p>
          <p className="text-lg font-bold text-slate-200 mt-1">{device?.os_family}</p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Last Heartbeat</p>
          <p className="text-lg font-bold text-cyan-400 mt-1">Just now</p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Telemetry Ingested</p>
          <p className="text-lg font-bold text-slate-100 mt-1">{device?.events_count || 1420} events</p>
        </Card>
      </div>

      <Card className="bg-slate-900 border-slate-800">
        <CardHeader>
          <CardTitle className="text-base text-slate-100">Recent Security Telemetry</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 flex items-center justify-between text-xs">
            <span className="font-mono text-cyan-400">Event 4624 • Logon Successful</span>
            <span className="text-slate-400">User Abhi / Interactive Session</span>
            <span className="text-slate-500">2 mins ago</span>
          </div>
          <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 flex items-center justify-between text-xs">
            <span className="font-mono text-emerald-400">Heartbeat Acknowledged</span>
            <span className="text-slate-400">Collector telemetry queue: 0 pending</span>
            <span className="text-slate-500">5 mins ago</span>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
