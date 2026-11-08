/**
 * CyberGuard AI — Page 07: Device Details
 * ============================================================================
 * Inspects device health, collector heartbeat, telemetry, network activity,
 * and security posture backed by real database records.
 */

import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { 
  Server, 
  ArrowLeft, 
  ShieldCheck, 
  AlertTriangle, 
  Clock, 
  Power,
  RefreshCw,
  Monitor,
  CheckCircle2,
  XCircle,
  AlertCircle
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Spinner } from "@/components/ui/Spinner";
import { api } from "@/lib/api";
import { formatRelativeTime } from "@/lib/utils";
import { toast } from "sonner";

interface DeviceFinding {
  id: string;
  finding_type: string;
  severity: string;
  title: string;
  description: string;
  created_at: string;
}

interface DeviceDetailsData {
  id: string;
  name: string;
  type: string;
  os_version: string | null;
  agent_version: string | null;
  hostname: string | null;
  ip_address: string | null;
  status: string;
  last_heartbeat: string | null;
  last_event_at: string | null;
  threat_count: number;
  collector_connected: boolean;
  source_key: string;
  created_at: string;
  findings: DeviceFinding[];
}

export default function DeviceDetails() {
  const { deviceId } = useParams<{ deviceId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const { data: device, isLoading, error } = useQuery<DeviceDetailsData>({
    queryKey: ["device-detail", deviceId],
    queryFn: async () => {
      const { data } = await api.get<DeviceDetailsData>(`/devices/${deviceId}`);
      return data;
    },
    refetchInterval: 10000,
  });

  const disconnectMutation = useMutation({
    mutationFn: async () => {
      await api.delete(`/devices/${deviceId}`);
    },
    onSuccess: () => {
      toast.success("Device removed and credentials revoked.");
      queryClient.invalidateQueries({ queryKey: ["devices"] });
      navigate("/personal/devices");
    },
    onError: (err: any) => {
      toast.error(err?.message || "Failed to remove device");
    },
  });

  const challengeMutation = useMutation({
    mutationFn: async () => {
      const { data } = await api.post(`/devices/${deviceId}/challenge`);
      return data;
    },
    onSuccess: () => {
      toast.success("Fresh enrollment challenge generated.");
      queryClient.invalidateQueries({ queryKey: ["device-detail", deviceId] });
    },
    onError: (err: any) => {
      toast.error(err?.message || "Failed to issue challenge");
    },
  });

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Spinner size="lg" label="Loading device telemetry..." />
      </div>
    );
  }

  if (error || !device) {
    return (
      <div className="space-y-6">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => navigate("/personal/devices")}
          className="text-slate-400 hover:text-slate-200"
        >
          <ArrowLeft size={16} className="mr-1" /> Back to Devices
        </Button>
        <Card className="border-rose-500/30 bg-rose-950/20 p-8 text-center">
          <AlertCircle className="mx-auto h-12 w-12 text-rose-400 mb-3" />
          <h3 className="text-lg font-bold text-rose-200">Device Not Found</h3>
          <p className="mt-1 text-sm text-slate-400 max-w-md mx-auto">
            This device does not exist or you do not have permission to inspect it.
          </p>
        </Card>
      </div>
    );
  }

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
            <Monitor size={28} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-bold text-slate-100">{device.name}</h1>
              {device.collector_connected ? (
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1">
                  <CheckCircle2 size={12} className="text-emerald-400" /> Online
                </span>
              ) : device.status === "pending_enrollment" || device.status === "pending" ? (
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/30 flex items-center gap-1">
                  <Clock size={12} className="text-amber-400" /> Pending Enrollment
                </span>
              ) : (
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-500/20 text-slate-400 border border-slate-500/30 flex items-center gap-1">
                  <XCircle size={12} className="text-slate-400" /> Offline
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Host: {device.hostname || "Unreported"} • Key: {device.source_key}
            </p>
          </div>
        </div>

        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => challengeMutation.mutate()}
            isLoading={challengeMutation.isPending}
            className="border-slate-700 text-slate-300 hover:bg-slate-800 text-xs"
          >
            <RefreshCw size={14} className="mr-1.5" /> Re-enroll Challenge
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              if (confirm("Are you sure you want to disconnect this device and revoke its tokens?")) {
                disconnectMutation.mutate();
              }
            }}
            isLoading={disconnectMutation.isPending}
            className="border-rose-500/30 text-rose-400 hover:bg-rose-500/10 text-xs"
          >
            <Power size={14} className="mr-1.5" /> Disconnect Device
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Collector Health</p>
          <p className={`text-lg font-bold mt-1 ${device.collector_connected ? "text-emerald-400" : "text-amber-400"}`}>
            {device.collector_connected ? "Healthy" : "Not connected"}
          </p>
          <p className="text-xs text-slate-500 mt-0.5">Agent: {device.agent_version || "Not installed"}</p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Operating System</p>
          <p className="text-lg font-bold text-slate-200 mt-1 capitalize">{device.type}</p>
          <p className="text-xs text-slate-500 mt-0.5">{device.os_version || "Platform standard"}</p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Last Heartbeat</p>
          <p className="text-lg font-bold text-cyan-400 mt-1">
            {device.last_heartbeat ? formatRelativeTime(device.last_heartbeat) : "Never"}
          </p>
          <p className="text-xs text-slate-500 mt-0.5">IP: {device.ip_address || "Awaiting stream"}</p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Threat Detections</p>
          <p className={`text-lg font-bold mt-1 ${device.threat_count > 0 ? "text-rose-400" : "text-emerald-400"}`}>
            {device.threat_count} detected
          </p>
          <p className="text-xs text-slate-500 mt-0.5">Findings: {device.findings?.length || 0}</p>
        </Card>
      </div>

      <Card className="bg-slate-900 border-slate-800">
        <CardHeader>
          <CardTitle className="text-base text-slate-100">Telemetry & Security Findings</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {(!device.findings || device.findings.length === 0) ? (
            <div className="py-8 text-center text-slate-500 text-sm">
              <ShieldCheck size={36} className="mx-auto mb-2 text-slate-600" />
              <p className="font-medium text-slate-400">No active security findings recorded</p>
              <p className="text-xs mt-1 text-slate-500">
                {device.collector_connected 
                  ? "Collector is running and no suspicious patterns have been detected."
                  : "Run the installation script to connect this device collector and begin log streaming."}
              </p>
            </div>
          ) : (
            device.findings.map((finding) => (
              <div 
                key={finding.id} 
                className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 flex items-center justify-between text-xs"
              >
                <div>
                  <div className="font-semibold text-slate-200">{finding.title}</div>
                  <div className="text-slate-400 mt-0.5">{finding.description}</div>
                </div>
                <div className="text-right shrink-0 ml-4">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                    finding.severity === "high" || finding.severity === "critical"
                      ? "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                      : "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                  }`}>
                    {finding.severity}
                  </span>
                  <div className="text-slate-500 text-[10px] mt-1 font-mono">
                    {formatRelativeTime(finding.created_at)}
                  </div>
                </div>
              </div>
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
}
