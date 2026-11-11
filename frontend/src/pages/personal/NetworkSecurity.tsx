/**
 * CyberGuard AI — Page 11: Network Security
 * ============================================================================
 * Reviews network flow telemetry, active sensors, suspicious outbound flows,
 * port scan attempts, and malicious IP correlation from PostgreSQL records.
 */

import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { 
  Wifi, 
  Globe, 
  ShieldAlert, 
  Radio, 
  Activity, 
  CheckCircle2, 
  AlertOctagon,
  RefreshCw,
  Copy,
  Check,
  Terminal,
  ShieldCheck,
  Sparkles,
  ArrowRight
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import {
  Modal,
  ModalContent,
  ModalHeader,
  ModalTitle,
  ModalDescription,
  ModalFooter,
} from "@/components/ui/Modal";
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

interface EnrolledSensorData {
  sensor_id: string;
  name: string;
  source_key: string;
  status: string;
  enrollment_token: string;
  docker_command: string;
  linux_probe_command: string;
  ingest_endpoint: string;
}

export default function NetworkSecurity() {
  const queryClient = useQueryClient();

  // Enroll modal state
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [sensorName, setSensorName] = useState("Primary Gateway Sensor");
  const [sensorType, setSensorType] = useState<"docker" | "linux" | "api">("docker");
  const [enrolledSensor, setEnrolledSensor] = useState<EnrolledSensorData | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isEnrolling, setIsEnrolling] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);

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

  const handleOpenEnrollModal = () => {
    setIsModalOpen(true);
  };

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
    toast.success("Copied to clipboard");
  };

  const handleEnrollSensor = async () => {
    if (!sensorName.trim()) {
      toast.error("Please enter a sensor or gateway name.");
      return;
    }
    setIsEnrolling(true);
    try {
      const { data } = await api.post<EnrolledSensorData>("/network/sensors/enroll", {
        name: sensorName.trim(),
        description: "Network flow inspection & egress monitoring gateway",
      });
      setEnrolledSensor(data);
      toast.success(`Network Sensor "${data.name}" enrolled!`);
      queryClient.invalidateQueries({ queryKey: ["network-summary"] });
      queryClient.invalidateQueries({ queryKey: ["devices"] });
    } catch (err: any) {
      toast.error(err?.message || "Failed to enroll network sensor.");
    } finally {
      setIsEnrolling(false);
    }
  };

  const handleVerifyFlows = async () => {
    if (!enrolledSensor) return;
    setIsVerifying(true);
    try {
      const { data } = await api.post(`/network/sensors/${enrolledSensor.sensor_id}/verify`);
      toast.success(
        `Verified! Ingested ${data.flows_ingested || 3} test flows into network telemetry.`
      );
      setEnrolledSensor(prev => prev ? { ...prev, status: "active" } : null);
      queryClient.invalidateQueries({ queryKey: ["network-summary"] });
      queryClient.invalidateQueries({ queryKey: ["network-flows"] });
      queryClient.invalidateQueries({ queryKey: ["devices"] });
    } catch (err: any) {
      toast.error(err?.message || "Verification failed. Check network connection.");
    } finally {
      setIsVerifying(false);
    }
  };

  const handleCloseModal = () => {
    setIsModalOpen(false);
    // Refresh queries on close if sensor was enrolled
    if (enrolledSensor) {
      refetch();
      queryClient.invalidateQueries({ queryKey: ["network-flows"] });
    }
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
            onClick={handleOpenEnrollModal}
            className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shadow-lg shadow-cyan-500/20"
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
            <CardTitle className="text-base text-slate-100 flex items-center justify-between">
              <span className="flex items-center gap-2">
                <Activity size={16} className="text-cyan-400" />
                Observed Network Flows & Telemetry
              </span>
              {net.sensors > 0 && (
                <span className="text-xs font-medium text-emerald-400 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  Live Sensor Feed Active
                </span>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {isSummaryLoading || isFlowsLoading ? (
              <div className="p-12 text-center text-sm text-slate-400">Polling network sensors...</div>
            ) : flows.length === 0 ? (
              <div className="py-12 text-center border-t border-slate-800/80">
                <Wifi className="w-10 h-10 text-slate-600 mx-auto mb-3" />
                <p className="text-sm font-semibold text-slate-300">No network sensor flows recorded yet</p>
                <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
                  Click <span className="text-cyan-400 font-semibold">"Enroll Network Sensor"</span> above to connect a Docker flow probe, gateway tap, or send a test verification flow batch.
                </p>
                <Button
                  size="sm"
                  onClick={handleOpenEnrollModal}
                  className="mt-4 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
                >
                  <Radio size={14} className="mr-1.5" /> Connect Network Sensor Now
                </Button>
              </div>
            ) : (
              <div className="space-y-3 font-mono text-xs">
                {flows.map((fl) => (
                  <div key={fl.id} className="p-3 bg-slate-950/70 rounded-lg border border-slate-800 flex items-center justify-between hover:border-slate-700 transition-colors">
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

      {/* ── Network Sensor Enrollment Modal ──────────────────────────────── */}
      <Modal open={isModalOpen} onOpenChange={handleCloseModal}>
        <ModalContent className="max-w-2xl bg-slate-900 border-slate-800 text-slate-100 max-h-[92vh] flex flex-col p-0 overflow-hidden">
          {/* Header */}
          <ModalHeader className="p-6 border-b border-slate-800/80 shrink-0">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                <Radio size={22} />
              </div>
              <div>
                <ModalTitle className="text-lg font-bold text-slate-100">
                  {enrolledSensor ? "Network Sensor Enrolled & Ready" : "Enroll Network Security Sensor"}
                </ModalTitle>
                <ModalDescription className="text-xs text-slate-400 mt-0.5">
                  {enrolledSensor
                    ? `Sensor "${enrolledSensor.name}" is registered in CyberGuard AI.`
                    : "Deploy a flow probe, gateway tap, or connect a firewall NetFlow log forwarder."}
                </ModalDescription>
              </div>
            </div>
          </ModalHeader>

          {/* Modal Body */}
          <div className="p-6 overflow-y-auto flex-1 space-y-5">
            {!enrolledSensor ? (
              /* Step 1: Form to enroll */
              <div className="space-y-5">
                <div>
                  <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
                    Sensor or Gateway Name
                  </label>
                  <Input
                    value={sensorName}
                    onChange={(e) => setSensorName(e.target.value)}
                    placeholder="e.g. Primary Gateway Sensor or Office Firewall Tap"
                    className="bg-slate-950 border-slate-800 text-slate-100 text-sm"
                  />
                  <p className="text-[11px] text-slate-500 mt-1.5">
                    This identifies your sensor in the dashboard and logs.
                  </p>
                </div>

                <div>
                  <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
                    Choose Deployment Architecture
                  </label>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <button
                      type="button"
                      onClick={() => setSensorType("docker")}
                      className={`p-3.5 rounded-xl border text-left transition-all ${
                        sensorType === "docker"
                          ? "border-cyan-500 bg-cyan-950/30 ring-1 ring-cyan-500/50"
                          : "border-slate-800 bg-slate-950/60 hover:border-slate-700"
                      }`}
                    >
                      <Terminal size={18} className="text-cyan-400 mb-2" />
                      <div className="text-xs font-bold text-slate-200">Docker Probe</div>
                      <p className="text-[11px] text-slate-400 mt-1">
                        Host network packet capture container (1 command).
                      </p>
                    </button>

                    <button
                      type="button"
                      onClick={() => setSensorType("linux")}
                      className={`p-3.5 rounded-xl border text-left transition-all ${
                        sensorType === "linux"
                          ? "border-cyan-500 bg-cyan-950/30 ring-1 ring-cyan-500/50"
                          : "border-slate-800 bg-slate-950/60 hover:border-slate-700"
                      }`}
                    >
                      <Radio size={18} className="text-cyan-400 mb-2" />
                      <div className="text-xs font-bold text-slate-200">Gateway Daemon</div>
                      <p className="text-[11px] text-slate-400 mt-1">
                        Lightweight probe for Linux, pfSense, or OpenWrt.
                      </p>
                    </button>

                    <button
                      type="button"
                      onClick={() => setSensorType("api")}
                      className={`p-3.5 rounded-xl border text-left transition-all ${
                        sensorType === "api"
                          ? "border-cyan-500 bg-cyan-950/30 ring-1 ring-cyan-500/50"
                          : "border-slate-800 bg-slate-950/60 hover:border-slate-700"
                      }`}
                    >
                      <Globe size={18} className="text-cyan-400 mb-2" />
                      <div className="text-xs font-bold text-slate-200">REST Ingestion</div>
                      <p className="text-[11px] text-slate-400 mt-1">
                        Stream Zeek, Suricata, or NetFlow JSON via API.
                      </p>
                    </button>
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-cyan-950/20 border border-cyan-800/40 text-xs text-cyan-300 flex items-start gap-2.5">
                  <ShieldCheck size={18} className="text-cyan-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold text-slate-200">Instant Telemetry Verification:</span> Once enrolled, CyberGuard AI automatically verifies flow inspection and enables live egress monitoring.
                  </div>
                </div>
              </div>
            ) : (
              /* Step 2: Enrolled & Deployment instructions */
              <div className="space-y-4">
                {/* Active sensor badge */}
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className={`w-2.5 h-2.5 rounded-full ${enrolledSensor.status === "active" ? "bg-emerald-400" : "bg-cyan-400"} animate-pulse`} />
                      <span className="text-sm font-bold text-slate-100">{enrolledSensor.name}</span>
                      <span className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded ${enrolledSensor.status === "active" ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30" : "bg-cyan-500/10 text-cyan-400 border border-cyan-500/30"}`}>
                        {enrolledSensor.status === "active" ? "Active • Verified" : "Ready • Awaiting Flows"}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 font-mono mt-1">
                      Sensor Key: {enrolledSensor.source_key} • ID: {enrolledSensor.sensor_id}
                    </p>
                  </div>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => handleCopy(enrolledSensor.enrollment_token, "token")}
                    className="border-slate-800 text-xs text-slate-300"
                  >
                    {copiedKey === "token" ? <Check size={14} className="mr-1 text-emerald-400" /> : <Copy size={14} className="mr-1" />}
                    {copiedKey === "token" ? "Copied Token" : "Copy Token"}
                  </Button>
                </div>

                {/* Architecture Selector Tabs */}
                <div className="flex border-b border-slate-800 text-xs font-semibold gap-4">
                  <button
                    type="button"
                    onClick={() => setSensorType("docker")}
                    className={`pb-2 transition-colors ${
                      sensorType === "docker"
                        ? "text-cyan-400 border-b-2 border-cyan-400"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    Docker Command
                  </button>
                  <button
                    type="button"
                    onClick={() => setSensorType("linux")}
                    className={`pb-2 transition-colors ${
                      sensorType === "linux"
                        ? "text-cyan-400 border-b-2 border-cyan-400"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    Linux / Gateway Shell
                  </button>
                  <button
                    type="button"
                    onClick={() => setSensorType("api")}
                    className={`pb-2 transition-colors ${
                      sensorType === "api"
                        ? "text-cyan-400 border-b-2 border-cyan-400"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    Webhook Ingestion API
                  </button>
                </div>

                {/* Code Snippet */}
                <div className="relative rounded-xl bg-slate-950 border border-slate-800 p-4 font-mono text-xs text-slate-300 overflow-x-auto">
                  <button
                    type="button"
                    onClick={() => {
                      const text =
                        sensorType === "docker"
                          ? enrolledSensor.docker_command
                          : sensorType === "linux"
                          ? enrolledSensor.linux_probe_command
                          : enrolledSensor.ingest_endpoint;
                      handleCopy(text, "cmd");
                    }}
                    className="absolute top-3 right-3 p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700/60"
                    title="Copy command"
                  >
                    {copiedKey === "cmd" ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
                  </button>

                  <pre className="pr-10 whitespace-pre-wrap leading-relaxed">
                    {sensorType === "docker"
                      ? enrolledSensor.docker_command
                      : sensorType === "linux"
                      ? enrolledSensor.linux_probe_command
                      : `POST ${enrolledSensor.ingest_endpoint}\nHeader: Content-Type: application/json\nHeader: X-Collector-Credential: ${enrolledSensor.enrollment_token}`}
                  </pre>
                </div>

                {/* Instant Verification Banner */}
                <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                  <div>
                    <h5 className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
                      <Sparkles size={14} className="text-cyan-400" />
                      Verify Sensor Flow Ingestion
                    </h5>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      Simulate a live gateway traffic batch to verify threat detection and populate your flow table immediately.
                    </p>
                  </div>

                  <Button
                    size="sm"
                    onClick={handleVerifyFlows}
                    isLoading={isVerifying}
                    className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shrink-0"
                  >
                    <Activity size={14} className="mr-1.5" /> Send Verification Flows
                  </Button>
                </div>
              </div>
            )}
          </div>

          {/* Footer */}
          <ModalFooter className="p-4 bg-slate-950 border-t border-slate-800/80 flex items-center justify-between shrink-0">
            {!enrolledSensor ? (
              <>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleCloseModal}
                  className="border-slate-800 text-slate-400"
                >
                  Cancel
                </Button>
                <Button
                  size="sm"
                  onClick={handleEnrollSensor}
                  isLoading={isEnrolling}
                  className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
                >
                  Generate Token & Enroll Sensor <ArrowRight size={14} className="ml-1.5" />
                </Button>
              </>
            ) : (
              <>
                <span className="text-xs text-slate-400">
                  Sensor registered under <span className="text-slate-200 font-semibold">{enrolledSensor.name}</span>
                </span>
                <Button
                  size="sm"
                  onClick={handleCloseModal}
                  className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs"
                >
                  Done & View Network Flows
                </Button>
              </>
            )}
          </ModalFooter>
        </ModalContent>
      </Modal>
    </div>
  );
}
