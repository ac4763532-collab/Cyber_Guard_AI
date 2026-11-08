/**
 * CyberGuard AI — Personal Dashboard (Page 5)
 * ============================================================================
 *
 * Dashboard for Individual/Normal Users - their personal security workspace.
 *
 * Flow from Page 2: UserSelection → /personal/dashboard
 *
 * Design: dark navy (#071321) background with cyan/blue accents, Inter font,
 * responsive grid, cards for devices, alerts, findings, quick actions.
 */

import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, AlertTriangle, Search, RefreshCw, Plus, Settings, Bell, FileText, Mail } from "lucide-react";
import { formatDistanceToNow } from "date-fns";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { TabsRoot as Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/Tabs";
import { cn } from "@/lib/utils";

interface Device {
  id: string;
  name: string;
  type: "mobile" | "desktop" | "tablet" | "server";
  status: "protected" | "at_risk" | "offline";
  last_scan: string;
  threat_count: number;
}

interface Alert {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  source: string;
  timestamp: string;
  status: "open" | "investigating" | "resolved" | "dismissed";
}

interface Finding {
  id: string;
  title: string;
  type: "phishing" | "malware" | "vulnerability" | "suspicious_activity" | "data_leak";
  risk_score: number;
  detected_at: string;
  status: "new" | "analyzing" | "remediated" | "false_positive";
}

// Mock data for Personal Dashboard
const mockDevices: Device[] = [
  { id: "1", name: "MacBook Pro", type: "desktop", status: "protected", last_scan: "2026-11-07T14:30:00Z", threat_count: 0 },
  { id: "2", name: "iPhone 15", type: "mobile", status: "protected", last_scan: "2026-11-07T10:15:00Z", threat_count: 0 },
  { id: "3", name: "iPad Pro", type: "tablet", status: "at_risk", last_scan: "2026-11-06T22:00:00Z", threat_count: 2 },
  { id: "4", name: "Home Server", type: "server", status: "offline", last_scan: "2026-11-05T08:00:00Z", threat_count: 0 },
];

const mockAlerts: Alert[] = [
  { id: "1", title: "Suspicious login detected on iPad Pro", severity: "high", source: "Device Monitor", timestamp: "2026-11-07T15:42:00Z", status: "open" },
  { id: "2", title: "Phishing email quarantined", severity: "medium", source: "Email Analysis Agent", timestamp: "2026-11-07T14:20:00Z", status: "resolved" },
  { id: "3", title: "Outdated OS version on Home Server", severity: "low", source: "Vulnerability Scanner", timestamp: "2026-11-06T18:00:00Z", status: "open" },
  { id: "4", title: "Network anomaly detected", severity: "critical", source: "Network Analysis Agent", timestamp: "2026-11-07T16:05:00Z", status: "investigating" },
];

const mockFindings: Finding[] = [
  { id: "1", title: "Credential stuffing attempt blocked", type: "suspicious_activity", risk_score: 85, detected_at: "2026-11-07T15:30:00Z", status: "remediated" },
  { id: "2", title: "Suspicious email attachment analyzed", type: "phishing", risk_score: 72, detected_at: "2026-11-07T14:15:00Z", status: "analyzing" },
  { id: "3", title: "CVE-2026-XXXX detected on Home Server", type: "vulnerability", risk_score: 68, detected_at: "2026-11-06T20:00:00Z", status: "new" },
  { id: "4", title: "Personal data found in dark web scan", type: "data_leak", risk_score: 91, detected_at: "2026-11-07T12:00:00Z", status: "new" },
];

const getSeverityColor = (severity: string) => {
  const colors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    low: "bg-green-500/20 text-green-400 border-green-500/30",
    info: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  };
  return colors[severity] || colors.info;
};

const getSeverityDotColor = (severity: string) => {
  const colors: Record<string, string> = {
    critical: "bg-red-500",
    high: "bg-orange-500",
    medium: "bg-amber-500",
    low: "bg-green-500",
    info: "bg-blue-500",
  };
  return colors[severity] || colors.info;
};

const getStatusColor = (status: string) => {
  const colors: Record<string, string> = {
    protected: "bg-green-500/20 text-green-400 border-green-500/30",
    at_risk: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    offline: "bg-slate-500/20 text-slate-400 border-slate-500/30",
    open: "bg-red-500/20 text-red-400 border-red-500/30",
    investigating: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    resolved: "bg-green-500/20 text-green-400 border-green-500/30",
    dismissed: "bg-slate-500/20 text-slate-400 border-slate-500/30",
    new: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    analyzing: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    remediated: "bg-green-500/20 text-green-400 border-green-500/30",
    false_positive: "bg-slate-500/20 text-slate-400 border-slate-500/30",
  };
  return colors[status] || colors.open;
};

export default function PersonalDashboard() {
  const navigate = useNavigate();
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<string>("overview");

  useEffect(() => {
    // Simulate loading
    const timer = setTimeout(() => setIsLoading(false), 800);
    return () => clearTimeout(timer);
  }, []);

  const handleQuickScan = () => {
    // Trigger a quick security scan
    console.log("Quick scan initiated");
  };

  const handleAddDevice = () => {
    navigate("/devices");
  };

  const handleViewAllAlerts = () => {
    setActiveTab("alerts");
  };

  const handleViewAllFindings = () => {
    setActiveTab("findings");
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-brand-400 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-slate-500 dark:text-slate-400">Loading your personal security dashboard...</p>
        </div>
      </div>
    );
  }

  const protectedDevices = mockDevices.filter(d => d.status === "protected").length;
  const atRiskDevices = mockDevices.filter(d => d.status === "at_risk").length;
  const openAlerts = mockAlerts.filter(a => a.status === "open" || a.status === "investigating").length;
  const criticalFindings = mockFindings.filter(f => f.risk_score >= 80).length;

  return (
    <div className="space-y-6">
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Personal Security Dashboard
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Monitor your devices, alerts, and security posture in one place.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" leftIcon={<RefreshCw size={16} />} onClick={() => setIsLoading(true)}>
            Refresh
          </Button>
          <Button variant="primary" size="sm" leftIcon={<Plus size={16} />} onClick={handleAddDevice}>
            Add Device
          </Button>
          <Button variant="secondary" size="sm" leftIcon={<Search size={16} />} onClick={handleQuickScan}>
            Quick Scan
          </Button>
        </div>
      </div>

      {/* ── Stats Cards ────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Protected Devices</p>
                <p className="text-3xl font-bold text-slate-900 dark:text-slate-100 mt-1">{protectedDevices}</p>
                <p className="text-xs text-green-500 mt-1">{mockDevices.length} total devices</p>
              </div>
              <div className="w-12 h-12 rounded-xl bg-green-500/10 flex items-center justify-center">
                <Shield className="w-6 h-6 text-green-500" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Devices at Risk</p>
                <p className="text-3xl font-bold text-slate-900 dark:text-slate-100 mt-1">{atRiskDevices}</p>
                <p className="text-xs text-orange-500 mt-1">Requires attention</p>
              </div>
              <div className="w-12 h-12 rounded-xl bg-orange-500/10 flex items-center justify-center">
                <AlertTriangle className="w-6 h-6 text-orange-500" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Active Alerts</p>
                <p className="text-3xl font-bold text-slate-900 dark:text-slate-100 mt-1">{openAlerts}</p>
                <p className="text-xs text-red-500 mt-1">Need review</p>
              </div>
              <div className="w-12 h-12 rounded-xl bg-red-500/10 flex items-center justify-center">
                <Bell className="w-6 h-6 text-red-500" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Critical Findings</p>
                <p className="text-3xl font-bold text-slate-900 dark:text-slate-100 mt-1">{criticalFindings}</p>
                <p className="text-xs text-red-500 mt-1">High risk score</p>
              </div>
              <div className="w-12 h-12 rounded-xl bg-red-500/10 flex items-center justify-center">
                <FileText className="w-6 h-6 text-red-500" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* ── Tabs ───────────────────────────────────────────────────────── */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="devices">Devices</TabsTrigger>
          <TabsTrigger value="alerts">Alerts</TabsTrigger>
          <TabsTrigger value="findings">Findings</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Recent Alerts */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle className="text-lg">Recent Security Alerts</CardTitle>
                <Button variant="ghost" size="sm" onClick={handleViewAllAlerts}>View All</Button>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {mockAlerts.slice(0, 4).map((alert) => (
                    <div key={alert.id} className="flex items-start gap-3 p-3 rounded-lg bg-slate-50 dark:bg-slate-900/50">
                      <div className={cn("w-2 h-2 rounded-full mt-2 flex-shrink-0", getSeverityDotColor(alert.severity))} />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-slate-900 dark:text-slate-100 truncate">{alert.title}</p>
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{alert.source} • {formatDistanceToNow(new Date(alert.timestamp), { addSuffix: true })}</p>
                      </div>
                      <Badge status={alert.status} withDot className={cn(getStatusColor(alert.status))} />
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Top Findings */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle className="text-lg">Top Risk Findings</CardTitle>
                <Button variant="ghost" size="sm" onClick={handleViewAllFindings}>View All</Button>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {mockFindings.slice(0, 4).map((finding) => (
                    <div key={finding.id} className="flex items-start gap-3 p-3 rounded-lg bg-slate-50 dark:bg-slate-900/50">
                      <div className="w-10 h-10 rounded-lg bg-brand-500/10 flex items-center justify-center flex-shrink-0">
                        <FileText className="w-5 h-5 text-brand-500" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-slate-900 dark:text-slate-100 truncate">{finding.title}</p>
                        <div className="flex items-center gap-2 mt-1">
                          <span className="text-xs text-slate-500 dark:text-slate-400">{finding.type.replace("_", " ")}</span>
                          <span className="text-xs font-medium text-red-500">Risk: {finding.risk_score}/100</span>
                        </div>
                      </div>
                      <Badge status={finding.status} withDot className={cn(getStatusColor(finding.status))} />
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Quick Actions */}
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Quick Actions</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <Button variant="outline" className="h-24 flex flex-col items-center justify-center gap-2" leftIcon={<Plus size={24} />} onClick={handleAddDevice}>
                  Add New Device
                </Button>
                <Button variant="outline" className="h-24 flex flex-col items-center justify-center gap-2" leftIcon={<Search size={24} />} onClick={handleQuickScan}>
                  Run Full Scan
                </Button>
                <Button variant="outline" className="h-24 flex flex-col items-center justify-center gap-2" leftIcon={<Mail size={24} />}>
                  Scan Email
                </Button>
                <Button variant="outline" className="h-24 flex flex-col items-center justify-center gap-2" leftIcon={<Settings size={24} />}>
                  Security Settings
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Devices Tab */}
        <TabsContent value="devices">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {mockDevices.map((device) => (
              <Card key={device.id}>
                <CardContent className="p-6">
                  <div className="flex items-start justify-between mb-4">
                    <div>
                      <h3 className="font-semibold text-slate-900 dark:text-slate-100">{device.name}</h3>
                      <p className="text-sm text-slate-500 dark:text-slate-400 capitalize">{device.type}</p>
                    </div>
                    <Badge status={device.status} withDot className={cn(getStatusColor(device.status))} />
                  </div>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between text-slate-500 dark:text-slate-400">
                      <span>Last Scan</span>
                      <span className="font-medium text-slate-900 dark:text-slate-100">{formatDistanceToNow(new Date(device.last_scan), { addSuffix: true })}</span>
                    </div>
                    <div className="flex justify-between text-slate-500 dark:text-slate-400">
                      <span>Threats Found</span>
                      <span className="font-medium text-slate-900 dark:text-slate-100">{device.threat_count}</span>
                    </div>
                  </div>
                  <div className="mt-4 flex gap-2">
                    <Button variant="outline" size="sm" className="flex-1" leftIcon={<Search size={14} />}>Scan Now</Button>
                    <Button variant="ghost" size="sm" className="flex-1" leftIcon={<Settings size={14} />}>Configure</Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Alerts Tab */}
        <TabsContent value="alerts">
          <div className="space-y-3">
            {mockAlerts.map((alert) => (
              <Card key={alert.id}>
                <CardContent className="p-4">
                  <div className="flex items-start gap-4">
                    <div className={cn("w-3 h-3 rounded-full mt-1.5 flex-shrink-0", getSeverityDotColor(alert.severity))} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between">
                        <h3 className="font-medium text-slate-900 dark:text-slate-100">{alert.title}</h3>
                        <Badge status={alert.severity} className={cn(getSeverityColor(alert.severity))} />
                      </div>
                      <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">{alert.source}</p>
                      <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">{formatDistanceToNow(new Date(alert.timestamp), { addSuffix: true })}</p>
                    </div>
                    <Badge status={alert.status} withDot className={cn(getStatusColor(alert.status))} />
                    <Button variant="ghost" size="sm" className="ml-2">View</Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Findings Tab */}
        <TabsContent value="findings">
          <div className="space-y-3">
            {mockFindings.map((finding) => (
              <Card key={finding.id}>
                <CardContent className="p-4">
                  <div className="flex items-start gap-4">
                    <div className="w-10 h-10 rounded-lg bg-brand-500/10 flex items-center justify-center flex-shrink-0">
                      <FileText className="w-5 h-5 text-brand-500" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between">
                        <h3 className="font-medium text-slate-900 dark:text-slate-100">{finding.title}</h3>
                        <Badge status={finding.status} withDot className={cn(getStatusColor(finding.status))} />
                      </div>
                      <div className="flex items-center gap-3 mt-1 text-sm">
                        <span className="text-slate-500 dark:text-slate-400 capitalize">{finding.type.replace("_", " ")}</span>
                        <span className="font-medium text-red-500">Risk Score: {finding.risk_score}/100</span>
                        <span className="text-slate-400 dark:text-slate-500">{formatDistanceToNow(new Date(finding.detected_at), { addSuffix: true })}</span>
                      </div>
                    </div>
                    <Button variant="ghost" size="sm">Investigate</Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}