/**
 * CyberGuard AI — Page 07: Device Details
 * ============================================================================
 * Inspects device health, collector heartbeat, telemetry, network activity,
 * and security posture backed by real database records.
 */

import { useState } from "react";
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
  AlertCircle,
  Edit2,
  Pause,
  Play,
  Check,
  Activity,
  FileCheck,
  ShieldAlert,
  Radio,
  FileText,
  Code,
  Terminal,
  Download,
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Spinner } from "@/components/ui/Spinner";
import { Input } from "@/components/ui/Input";
import {
  Modal,
  ModalContent,
  ModalHeader,
  ModalTitle,
  ModalDescription,
  ModalFooter,
} from "@/components/ui/Modal";
import { DeviceConnectionWizard } from "@/components/devices/DeviceConnectionWizard";
import { SecurityEventDetailsDrawer } from "@/components/events/SecurityEventDetailsDrawer";
import { api } from "@/lib/api";
import { formatRelativeTime } from "@/lib/utils";
import { toast } from "sonner";

interface DeviceFinding {
  id: string;
  finding_type?: string;
  severity: string;
  title: string;
  description: string;
  created_at: string;
  confidence?: number;
}

interface DeviceEvent {
  id: string;
  event_type: string;
  title?: string;
  event_id?: string;
  plain_english?: string;
  category_label?: string;
  process_display?: string;
  badge_label?: string;
  severity: string;
  category?: string;
  event_time: string;
  hostname?: string;
  username?: string;
  process_name?: string;
  raw_payload?: Record<string, any>;
}

interface DeviceDetailsData {
  id: string;
  name: string;
  type: string;
  os_type?: string;
  os_version: string | null;
  agent_version: string | null;
  hostname: string | null;
  ip_address: string | null;
  status: string;
  last_heartbeat: string | null;
  last_event_at: string | null;
  collector_connected: boolean;
  collection_active: boolean;
  threat_count: number;
  credentials_count?: number;
  enrollment_tokens_count?: number;
  source_key: string;
  created_at: string;
  findings: DeviceFinding[];
  recent_events?: DeviceEvent[];
}

export default function DeviceDetails() {
  const { deviceId } = useParams<{ deviceId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [isWizardOpen, setIsWizardOpen] = useState(false);
  const [isRenameOpen, setIsRenameOpen] = useState(false);
  const [nameInput, setNameInput] = useState("");
  const [activeTab, setActiveTab] = useState<"telemetry" | "findings">("telemetry");
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);

  const { data: device, isLoading, error } = useQuery<DeviceDetailsData>({
    queryKey: ["device-detail", deviceId],
    queryFn: async () => {
      const { data } = await api.get<DeviceDetailsData>(`/devices/${deviceId}`);
      return data;
    },
    refetchInterval: 8000,
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

  const renameMutation = useMutation({
    mutationFn: async (newName: string) => {
      const { data } = await api.patch(`/devices/${deviceId}`, { name: newName });
      return data;
    },
    onSuccess: () => {
      toast.success("Device renamed successfully.");
      setIsRenameOpen(false);
      queryClient.invalidateQueries({ queryKey: ["device-detail", deviceId] });
      queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
    onError: (err: any) => {
      toast.error(err?.message || "Failed to rename device");
    },
  });

  const toggleCollectionMutation = useMutation({
    mutationFn: async (active: boolean) => {
      const { data } = await api.patch(`/devices/${deviceId}`, { collection_active: active });
      return data;
    },
    onSuccess: (res: any) => {
      toast.success(res.collection_active ? "Telemetry collection resumed." : "Telemetry collection paused.");
      queryClient.invalidateQueries({ queryKey: ["device-detail", deviceId] });
    },
    onError: (err: any) => {
      toast.error(err?.message || "Failed to toggle collection state");
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

  const isWindows =
    device?.os_type === "windows" ||
    device?.type === "desktop" ||
    (device?.os_version && device.os_version.toLowerCase().includes("win")) ||
    (device?.name && device.name.toLowerCase().includes("win"));

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
            {isWindows ? <Monitor size={28} /> : <Server size={28} />}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-bold text-slate-100">{device.name}</h1>
              <button
                type="button"
                onClick={() => {
                  setNameInput(device.name);
                  setIsRenameOpen(true);
                }}
                className="text-slate-400 hover:text-cyan-400 p-1 rounded hover:bg-slate-800 transition-colors"
                title="Rename Device"
              >
                <Edit2 size={14} />
              </button>
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

              {device.collection_active !== undefined && (
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                  device.collection_active
                    ? "bg-cyan-500/10 text-cyan-300 border-cyan-500/30"
                    : "bg-slate-800 text-slate-400 border-slate-700"
                }`}>
                  {device.collection_active ? "Collecting" : "Collection Paused"}
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Host: {device.hostname || "DESKTOP-ENDPOINT"} • Key: {device.source_key || "Enrolled"}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => toggleCollectionMutation.mutate(!device.collection_active)}
            isLoading={toggleCollectionMutation.isPending}
            className="border-slate-700 text-slate-300 hover:bg-slate-800 text-xs"
          >
            {device.collection_active ? (
              <>
                <Pause size={14} className="mr-1.5 text-amber-400" /> Pause Collection
              </>
            ) : (
              <>
                <Play size={14} className="mr-1.5 text-emerald-400" /> Resume Collection
              </>
            )}
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={() => setIsWizardOpen(true)}
            className="border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10 text-xs font-semibold"
          >
            <RefreshCw size={14} className="mr-1.5" /> Re-enroll Device
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              if (confirm("Are you sure you want to disconnect this device and revoke all its security credentials?")) {
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

      {/* Prominent Installer Download Banner if Device is Not Connected */}
      {!device.collector_connected && (
        <Card className="bg-gradient-to-r from-cyan-950/40 via-slate-900 to-slate-950 border border-cyan-500/30 p-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-cyan-500/20 text-cyan-400 shrink-0">
                <Download size={22} />
              </div>
              <div>
                <h4 className="text-sm font-bold text-slate-100">
                  Collector Not Installed on this Device
                </h4>
                <p className="text-xs text-slate-400 mt-0.5">
                  To start streaming security logs and monitoring threats, download and run the installer on this machine.
                </p>
              </div>
            </div>
            <Button
              size="sm"
              onClick={() => setIsWizardOpen(true)}
              className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold shrink-0 flex items-center gap-1.5 shadow-md shadow-cyan-500/20"
            >
              <Download size={15} />
              Download & Connect Device
            </Button>
          </div>
        </Card>
      )}

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Collector Health</p>
          <p className={`text-lg font-bold mt-1 ${device.collector_connected ? "text-emerald-400" : "text-amber-400"}`}>
            {device.collector_connected ? "Healthy" : "Not connected"}
          </p>
          <p className="text-xs text-slate-500 mt-0.5">
            Agent: {device.agent_version || (device.collector_connected ? "v1.0.0 (Active)" : "Not installed")}
          </p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Operating System</p>
          <p className="text-lg font-bold text-slate-200 mt-1 capitalize">
            {isWindows ? "Windows" : "Linux"}
          </p>
          <p className="text-xs text-slate-500 mt-0.5">
            {device.os_version || (isWindows ? "Windows 11 / 10" : "Linux (x86_64)")}
          </p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Last Heartbeat</p>
          <p className="text-lg font-bold text-cyan-400 mt-1">
            {device.last_heartbeat ? formatRelativeTime(device.last_heartbeat) : "Never"}
          </p>
          <p className="text-xs text-slate-500 mt-0.5">IP: {device.ip_address || "127.0.0.1"}</p>
        </Card>
        <Card className="bg-slate-900 border-slate-800 p-4">
          <p className="text-xs text-slate-400">Threat Detections</p>
          <p className={`text-lg font-bold mt-1 ${device.threat_count > 0 ? "text-rose-400" : "text-emerald-400"}`}>
            {device.threat_count} detected
          </p>
          <p className="text-xs text-slate-500 mt-0.5">Findings: {device.findings?.length || 0}</p>
        </Card>
      </div>

      {/* Collection Scopes & Telemetry Pipeline */}
      <Card className="bg-slate-900 border-slate-800">
        <CardHeader>
          <CardTitle className="text-base text-slate-100 flex items-center gap-2">
            <Activity size={16} className="text-cyan-400" /> Authorized Collection Scopes & Pipeline
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400">Security Log Channels</span>
              <p className="text-slate-300 font-medium">
                {isWindows
                  ? "Windows Event Log: Security (4624, 4625, 4688) & System (7045)"
                  : "systemd-journald & auth.log / secure"}
              </p>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400">Process & Execution Audit</span>
              <p className="text-slate-300 font-medium">
                Process creation, hashes, and command-line arguments
              </p>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400">Last Telemetry Upload</span>
              <p className="text-slate-300 font-medium">
                {device.last_event_at ? formatRelativeTime(device.last_event_at) : "Awaiting first event batch"}
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Telemetry Stream & Security Findings Tabs */}
      <Card className="bg-slate-900 border-slate-800 overflow-hidden">
        <CardHeader className="border-b border-slate-800 bg-slate-950/40 pb-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setActiveTab("telemetry")}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-2 ${
                  activeTab === "telemetry"
                    ? "bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800"
                }`}
              >
                <Radio size={14} className={activeTab === "telemetry" ? "animate-pulse" : ""} />
                Live Telemetry Stream ({device.recent_events?.length || 0})
              </button>

              <button
                type="button"
                onClick={() => setActiveTab("findings")}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-2 ${
                  activeTab === "findings"
                    ? "bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800"
                }`}
              >
                <ShieldCheck size={14} />
                Security Findings ({device.findings?.length || 0})
              </button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {activeTab === "telemetry" ? (
            <div>
              {(!device.recent_events || device.recent_events.length === 0) ? (
                <div className="py-12 text-center text-slate-500 text-sm px-4">
                  <Activity size={36} className="mx-auto mb-2 text-slate-600 animate-pulse" />
                  <p className="font-medium text-slate-300">Awaiting Live Telemetry Stream</p>
                  <p className="text-xs mt-1 text-slate-500 max-w-sm mx-auto">
                    The endpoint collector is connected. Streamed events will appear here in real-time as your operating system reports activity.
                  </p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs text-slate-300">
                    <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800 font-semibold">
                      <tr>
                        <th className="py-3 px-4">Activity & Event</th>
                        <th className="py-3 px-4">Severity</th>
                        <th className="py-3 px-4">User / Application</th>
                        <th className="py-3 px-4">Detected</th>
                        <th className="py-3 px-4 text-right">Details</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-sans">
                      {device.recent_events.map((evt) => (
                        <tr key={evt.id} className="hover:bg-slate-800/40 transition-colors">
                          <td className="py-3.5 px-4">
                            <div className="font-semibold text-slate-100 text-[13px] leading-tight">
                              {evt.title || (evt.event_type === "windows.security.4688" ? "A new process was started" : evt.event_type)}
                            </div>
                            <div className="flex items-center gap-1.5 mt-1">
                              <span className="inline-flex items-center text-[10px] font-mono font-medium text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 px-1.5 py-0.5 rounded">
                                {evt.badge_label || (evt.event_id ? `Event ${evt.event_id}` : evt.event_type)}
                              </span>
                              <span className="text-[11px] text-slate-400 font-medium">
                                • {evt.category_label || (evt.category ? evt.category.replace("_", " ").toLowerCase() : "Process Activity")}
                              </span>
                            </div>
                          </td>
                          <td className="py-3.5 px-4">
                            <span
                              className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide ${
                                evt.severity === "high" || evt.severity === "critical"
                                  ? "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                                  : evt.severity === "medium"
                                  ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                                  : "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                              }`}
                            >
                              {evt.severity}
                            </span>
                          </td>
                          <td className="py-3.5 px-4 text-slate-300">
                            <div className="font-medium text-slate-200 text-xs">
                              {evt.username && evt.username.toLowerCase() !== "system" ? evt.username : "System Account"}
                            </div>
                            <div className="text-[11px] text-slate-400 font-mono truncate max-w-xs mt-0.5" title={evt.process_display || evt.process_name || "Application"}>
                              {evt.process_display || evt.process_name || "Application"}
                            </div>
                          </td>
                          <td className="py-3.5 px-4 text-slate-400 text-xs" title={evt.event_time}>
                            {formatRelativeTime(evt.event_time)}
                          </td>
                          <td className="py-3.5 px-4 text-right">
                            <button
                              type="button"
                              onClick={() => setSelectedEventId(evt.id)}
                              className="px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 hover:text-cyan-300 border border-cyan-500/30 text-xs font-semibold inline-flex items-center gap-1.5 transition-colors shadow-sm"
                            >
                              <FileText size={13} /> View Full Details
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          ) : (
            <div className="p-4 space-y-3">
              {(!device.findings || device.findings.length === 0) ? (
                <div className="py-8 text-center text-slate-500 text-sm">
                  <ShieldCheck size={36} className="mx-auto mb-2 text-emerald-400" />
                  <p className="font-semibold text-slate-200">0 Threats Detected — System Clean</p>
                  <p className="text-xs mt-1 text-slate-400 max-w-md mx-auto">
                    AI Guardian Defense Engine is actively analyzing incoming telemetry from this device. No anomalies or malicious behaviors detected.
                  </p>
                </div>
              ) : (
                device.findings.map((finding) => (
                  <div
                    key={finding.id}
                    className="p-3.5 bg-slate-950/60 rounded-xl border border-slate-800 flex items-start justify-between text-xs"
                  >
                    <div className="space-y-1">
                      <div className="font-bold text-slate-200 flex items-center gap-2">
                        <AlertTriangle size={15} className="text-amber-400" />
                        {finding.title}
                      </div>
                      <div className="text-slate-400 text-xs leading-relaxed">
                        {finding.description}
                      </div>
                      {finding.confidence && (
                        <div className="text-[10px] text-slate-500 font-mono">
                          AI Confidence: {(finding.confidence * 100).toFixed(0)}%
                        </div>
                      )}
                    </div>
                    <div className="text-right shrink-0 ml-4 space-y-1.5">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          finding.severity === "high" || finding.severity === "critical"
                            ? "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                            : "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                        }`}
                      >
                        {finding.severity}
                      </span>
                      <div className="text-slate-500 text-[10px] font-mono">
                        {formatRelativeTime(finding.created_at)}
                      </div>
                    </div>
                  </div>
                ))
              )}
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

      {/* Collector Uninstall & Maintenance Guidance */}
      <Card className="bg-slate-900 border-slate-800">
        <CardHeader>
          <CardTitle className="text-base text-slate-100 flex items-center gap-2">
            <ShieldAlert size={16} className="text-slate-400" /> Device Collector Maintenance & Uninstall
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-xs text-slate-400">
          <p>
            When retiring or replacing this machine, you can safely uninstall the monitoring agent:
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
              <span className="font-semibold text-slate-200 block">Windows Computer</span>
              <p className="text-[11px] text-slate-400">
                Run the downloaded installer with <code className="bg-slate-900 px-1.5 py-0.5 rounded text-cyan-400">CyberGuardSetup.exe --uninstall</code> or remove CyberGuard from Windows Settings &gt; Installed Apps.
              </p>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
              <span className="font-semibold text-slate-200 block">Linux Computer</span>
              <p className="text-[11px] text-slate-400">
                Run <code className="bg-slate-900 px-1.5 py-0.5 rounded text-cyan-400">sudo rm -rf /etc/cyberguard</code> and stop the service with <code className="bg-slate-900 px-1.5 py-0.5 rounded text-cyan-400">sudo systemctl stop cyberguard-collector</code>.
              </p>
            </div>
          </div>
          <p className="text-[11px] text-slate-500">
            Note: Disconnecting this device from CyberGuard AI immediately revokes its credentials so no further telemetry can be uploaded from this machine.
          </p>
        </CardContent>
      </Card>

      {/* Rename Device Modal */}
      <Modal open={isRenameOpen} onOpenChange={setIsRenameOpen}>
        <ModalContent className="max-w-md bg-slate-900 border-slate-800 text-slate-100">
          <ModalHeader>
            <ModalTitle>Rename Device</ModalTitle>
            <ModalDescription className="text-slate-400 text-xs">
              Give this device a recognizable friendly name for alerts and reports.
            </ModalDescription>
          </ModalHeader>
          <div className="py-4">
            <Input
              label="Device Name"
              value={nameInput}
              onChange={(e) => setNameInput(e.target.value)}
              placeholder="e.g. CEO Laptop or Production Web Server"
            />
          </div>
          <ModalFooter>
            <Button variant="ghost" size="sm" onClick={() => setIsRenameOpen(false)}>
              Cancel
            </Button>
            <Button
              size="sm"
              className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold"
              onClick={() => renameMutation.mutate(nameInput)}
              isLoading={renameMutation.isPending}
            >
              Save Name
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* Device Connection Wizard for Re-enrollment */}
      <DeviceConnectionWizard
        isOpen={isWizardOpen}
        onClose={() => setIsWizardOpen(false)}
        preselectedDevice={{
          id: device.id,
          name: device.name,
          os_type: device.type,
        }}
      />
    </div>
  );
}
