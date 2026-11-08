/**
 * CyberGuard AI — Personal Dashboard (Page 5)
 * ============================================================================
 * Live security posture dashboard for individual users backed by PostgreSQL.
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Shield, AlertTriangle, RefreshCw, Plus, Bell, FileText, CheckCircle2, Laptop } from "lucide-react";
import { formatDistanceToNow } from "date-fns";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { TabsRoot as Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/Tabs";
import { api } from "@/lib/api";
import { toast } from "sonner";

interface PersonalDashboardData {
  devices_count: number;
  devices_protected: number;
  devices_at_risk: number;
  devices_offline: number;
  alerts_active: number;
  alerts_critical: number;
  threat_score: number;
  findings_count: number;
  last_scan_at: string | null;
  devices: Array<{
    id: string;
    name: string;
    type: string;
    status: string;
    last_scan: string | null;
    threat_count: number;
  }>;
  recent_alerts: Array<{
    id: string;
    title: string;
    severity: string;
    source: string;
    timestamp: string;
    status: string;
  }>;
  recent_findings: Array<{
    id: string;
    title: string;
    type: string;
    risk_score: number;
    detected_at: string;
    status: string;
  }>;
}

const getSeverityColor = (severity: string) => {
  const colors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    low: "bg-green-500/20 text-green-400 border-green-500/30",
    info: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  };
  return colors[severity.toLowerCase()] || colors.info;
};

const getStatusColor = (status: string) => {
  const colors: Record<string, string> = {
    protected: "bg-green-500/20 text-green-400 border-green-500/30",
    at_risk: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    offline: "bg-slate-500/20 text-slate-400 border-slate-500/30",
    pending: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    open: "bg-red-500/20 text-red-400 border-red-500/30",
    investigating: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    resolved: "bg-green-500/20 text-green-400 border-green-500/30",
  };
  return colors[status.toLowerCase()] || colors.open;
};

export default function PersonalDashboard() {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<string>("overview");

  const { data, isLoading, refetch, isFetching } = useQuery<PersonalDashboardData>({
    queryKey: ["dashboard-personal"],
    queryFn: async () => {
      const res = await api.get<PersonalDashboardData>("/dashboard/personal");
      return res.data;
    },
    refetchInterval: 30_000,
  });

  const handleAddDevice = () => {
    navigate("/devices");
  };

  const handleQuickScan = () => {
    toast.info("Triggered endpoint vulnerability and telemetry scan.");
    refetch();
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-cyan-400 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-slate-400">Loading your verified security posture...</p>
        </div>
      </div>
    );
  }

  const d = data || {
    devices_count: 0,
    devices_protected: 0,
    devices_at_risk: 0,
    devices_offline: 0,
    alerts_active: 0,
    alerts_critical: 0,
    threat_score: 0,
    findings_count: 0,
    last_scan_at: null,
    devices: [],
    recent_alerts: [],
    recent_findings: [],
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-2 py-0.5 rounded-full">
            Workspace • Individual
          </span>
          <h1 className="text-2xl font-black text-slate-100 tracking-tight mt-2">
            Personal Security Dashboard
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Real-time telemetry, enrolled devices, and active threat detections.
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
            size="sm"
            onClick={handleAddDevice}
            className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold"
          >
            <Plus size={14} className="mr-1.5" /> Add Device
          </Button>
        </div>
      </div>

      {/* ── KPI Cards ─────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-slate-900 border-slate-800">
          <CardContent className="p-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Protected Devices</p>
                <p className="text-2xl font-black text-slate-100 mt-1">{d.devices_protected}</p>
                <p className="text-xs text-slate-400 mt-1">{d.devices_count} total enrolled</p>
              </div>
              <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
                <Shield className="w-5 h-5 text-emerald-400" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900 border-slate-800">
          <CardContent className="p-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Devices at Risk</p>
                <p className="text-2xl font-black text-amber-400 mt-1">{d.devices_at_risk}</p>
                <p className="text-xs text-slate-400 mt-1">{d.devices_offline} offline</p>
              </div>
              <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center">
                <AlertTriangle className="w-5 h-5 text-amber-400" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900 border-slate-800">
          <CardContent className="p-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Alerts</p>
                <p className="text-2xl font-black text-rose-400 mt-1">{d.alerts_active}</p>
                <p className="text-xs text-slate-400 mt-1">{d.alerts_critical} critical / high</p>
              </div>
              <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center">
                <Bell className="w-5 h-5 text-rose-400" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900 border-slate-800">
          <CardContent className="p-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Threat Posture Score</p>
                <p className="text-2xl font-black text-slate-100 mt-1">{d.threat_score}/100</p>
                <p className="text-xs text-emerald-400 mt-1">{d.threat_score <= 20 ? "Safe status" : "Action required"}</p>
              </div>
              <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
                <CheckCircle2 className="w-5 h-5 text-cyan-400" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* ── Tabs Navigation ───────────────────────────────────────────── */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-slate-900 border border-slate-800 p-1">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="devices">Devices ({d.devices_count})</TabsTrigger>
          <TabsTrigger value="alerts">Alerts ({d.alerts_active})</TabsTrigger>
          <TabsTrigger value="findings">Findings ({d.findings_count})</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6 mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            {/* Devices Summary */}
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-base font-bold text-slate-100">Enrolled Devices</CardTitle>
                <Button variant="ghost" size="sm" onClick={() => navigate("/devices")} className="text-xs text-cyan-400">
                  Manage Devices →
                </Button>
              </CardHeader>
              <CardContent>
                {d.devices.length === 0 ? (
                  <div className="py-8 text-center border border-dashed border-slate-800 rounded-xl">
                    <Laptop className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                    <p className="text-sm font-semibold text-slate-300">No devices enrolled yet</p>
                    <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
                      Install the CyberGuard collector on your Windows or Linux host to start receiving live security telemetry.
                    </p>
                    <Button size="sm" onClick={handleAddDevice} className="mt-4 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs">
                      <Plus size={14} className="mr-1" /> Enroll First Device
                    </Button>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {d.devices.slice(0, 4).map((dev) => (
                      <div key={dev.id} className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-xl flex items-center justify-between">
                        <div>
                          <p className="text-sm font-bold text-slate-200">{dev.name}</p>
                          <p className="text-xs text-slate-400 capitalize">{dev.type} • {dev.threat_count} threats detected</p>
                        </div>
                        <Badge className={getStatusColor(dev.status)}>{dev.status.replace("_", " ")}</Badge>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Active Alerts Summary */}
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-base font-bold text-slate-100">Recent Security Alerts</CardTitle>
                <Button variant="ghost" size="sm" onClick={() => navigate("/alerts")} className="text-xs text-cyan-400">
                  View Alert Center →
                </Button>
              </CardHeader>
              <CardContent>
                {d.recent_alerts.length === 0 ? (
                  <div className="py-8 text-center border border-dashed border-slate-800 rounded-xl">
                    <CheckCircle2 className="w-8 h-8 text-emerald-500/40 mx-auto mb-2" />
                    <p className="text-sm font-semibold text-slate-300">No active alerts</p>
                    <p className="text-xs text-slate-500 mt-1">Your protected workspace has no unacknowledged threats.</p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {d.recent_alerts.slice(0, 4).map((alt) => (
                      <div key={alt.id} className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-xl flex items-center justify-between">
                        <div>
                          <p className="text-sm font-bold text-slate-200">{alt.title}</p>
                          <p className="text-xs text-slate-400">{alt.source} • {formatDistanceToNow(new Date(alt.timestamp), { addSuffix: true })}</p>
                        </div>
                        <Badge className={getSeverityColor(alt.severity)}>{alt.severity}</Badge>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

          </div>
        </TabsContent>

        {/* Devices Tab */}
        <TabsContent value="devices" className="mt-4">
          <Card className="bg-slate-900 border-slate-800">
            <CardHeader>
              <CardTitle className="text-base text-slate-100">Enrolled Devices Fleet</CardTitle>
            </CardHeader>
            <CardContent>
              {d.devices.length === 0 ? (
                <div className="text-center py-12">
                  <p className="text-sm text-slate-400">No devices connected. Click "Add Device" above to enroll a host.</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {d.devices.map((dev) => (
                    <div key={dev.id} className="p-4 bg-slate-950/70 border border-slate-800 rounded-xl flex items-center justify-between">
                      <div>
                        <p className="font-bold text-slate-200">{dev.name}</p>
                        <p className="text-xs text-slate-400 mt-0.5">Type: {dev.type} • Status: {dev.status}</p>
                      </div>
                      <Badge className={getStatusColor(dev.status)}>{dev.status}</Badge>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Alerts Tab */}
        <TabsContent value="alerts" className="mt-4">
          <Card className="bg-slate-900 border-slate-800">
            <CardHeader>
              <CardTitle className="text-base text-slate-100">All Security Alerts</CardTitle>
            </CardHeader>
            <CardContent>
              {d.recent_alerts.length === 0 ? (
                <p className="text-center text-sm text-slate-400 py-12">No security alerts recorded.</p>
              ) : (
                <div className="space-y-3">
                  {d.recent_alerts.map((alt) => (
                    <div key={alt.id} className="p-4 bg-slate-950/70 border border-slate-800 rounded-xl flex items-center justify-between">
                      <div>
                        <p className="font-bold text-slate-200">{alt.title}</p>
                        <p className="text-xs text-slate-400 mt-0.5">{alt.source} • {alt.status}</p>
                      </div>
                      <Badge className={getSeverityColor(alt.severity)}>{alt.severity}</Badge>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Findings Tab */}
        <TabsContent value="findings" className="mt-4">
          <Card className="bg-slate-900 border-slate-800">
            <CardHeader>
              <CardTitle className="text-base text-slate-100">Agent Detection Findings</CardTitle>
            </CardHeader>
            <CardContent>
              {d.recent_findings.length === 0 ? (
                <p className="text-center text-sm text-slate-400 py-12">No detection findings generated by security agents.</p>
              ) : (
                <div className="space-y-3">
                  {d.recent_findings.map((f) => (
                    <div key={f.id} className="p-4 bg-slate-950/70 border border-slate-800 rounded-xl flex items-center justify-between">
                      <div>
                        <p className="font-bold text-slate-200">{f.title}</p>
                        <p className="text-xs text-slate-400 mt-0.5">Category: {f.type} • Confidence: {f.risk_score}%</p>
                      </div>
                      <Badge className="bg-cyan-500/20 text-cyan-300 border-cyan-500/30">{f.status}</Badge>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
