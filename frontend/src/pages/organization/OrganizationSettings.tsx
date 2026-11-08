/**
 * CyberGuard AI — Page 55: Organization Settings & Compliance Policies
 * ============================================================================
 * Enterprise tenant governance: API key management, audit retention policies,
 * SSO integration, and billing subscription tiers.
 */

import { useState } from "react";
import { 
  Building2, 
  Key, 
  ShieldCheck, 
  Lock, 
  Save, 
  CheckCircle2, 
  Copy, 
  Check, 
  CreditCard 
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { toast } from "sonner";

export default function OrganizationSettings() {
  const [activeTab, setActiveTab] = useState<"general" | "keys" | "compliance" | "billing">("general");
  const [copiedKey, setCopiedKey] = useState(false);

  const apiKey = "cg_live_sec_9941a87b41e8c04901f481";

  const handleCopy = () => {
    navigator.clipboard.writeText(apiKey);
    setCopiedKey(true);
    toast.success("Organization API key copied.");
    setTimeout(() => setCopiedKey(false), 2000);
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-2 py-0.5 rounded-full">
            Page 55 • Organization Governance
          </span>
          <h1 className="text-3xl font-black text-slate-100 tracking-tight mt-2">
            Organization Settings & Compliance
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Manage corporate API keys, log retention windows, and enterprise subscription settings.
          </p>
        </div>

        <Button onClick={() => toast.success("Settings saved.")} className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs">
          <Save className="w-4 h-4 mr-1.5" /> Save Configuration
        </Button>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-slate-800 pb-3">
        {[
          { id: "general", label: "Organization Profile", icon: Building2 },
          { id: "keys", label: "Tenant API Keys", icon: Key },
          { id: "compliance", label: "Compliance & Retention", icon: ShieldCheck },
          { id: "billing", label: "Subscription & Invoices", icon: CreditCard },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
                isActive
                  ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/30"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
              }`}
            >
              <Icon className="w-4 h-4" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {activeTab === "general" && (
        <Card className="border-slate-800 bg-slate-900/60">
          <CardHeader>
            <CardTitle className="text-slate-200 text-base">Corporate Profile</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">Company Legal Name</label>
                <Input defaultValue="CyberGuard Enterprise Corp" className="bg-slate-950 border-slate-800 text-slate-200 text-sm" />
              </div>
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">Primary Domain</label>
                <Input defaultValue="cyberguard-corp.internal" className="bg-slate-950 border-slate-800 text-slate-200 text-sm" />
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {activeTab === "keys" && (
        <Card className="border-slate-800 bg-slate-900/60">
          <CardHeader>
            <CardTitle className="text-slate-200 text-base">Collector Agent Enrollment Token</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-xs text-slate-400">
              This key is used by Windows and Linux collectors to register new devices directly to your organization.
            </p>
            <div className="flex items-center gap-2">
              <Input
                readOnly
                value={apiKey}
                className="bg-slate-950 border-slate-800 text-cyan-400 font-mono text-xs flex-1"
              />
              <Button onClick={handleCopy} variant="outline" className="border-slate-800 text-slate-200 text-xs">
                {copiedKey ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {activeTab === "compliance" && (
        <Card className="border-slate-800 bg-slate-900/60">
          <CardHeader>
            <CardTitle className="text-slate-200 text-base">Log & Telemetry Retention</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">Raw Evidence Storage Duration</label>
              <select className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500">
                <option>90 Days (SOC 2 Standard)</option>
                <option>180 Days (HIPAA Compliant)</option>
                <option>365 Days (Full Forensic Archival)</option>
              </select>
            </div>
          </CardContent>
        </Card>
      )}

      {activeTab === "billing" && (
        <Card className="border-slate-800 bg-slate-900/60">
          <CardHeader>
            <CardTitle className="text-slate-200 text-base">Enterprise Subscription</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
              <div>
                <p className="text-sm font-bold text-slate-100">Enterprise Shield Tier</p>
                <p className="text-xs text-slate-400">Unlimited War Rooms • Up to 250 Enrolled Endpoints • Priority Analyst SLA</p>
              </div>
              <span className="text-xs font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-3 py-1 rounded-full">
                Active
              </span>
            </div>
          </CardContent>
        </Card>
      )}

    </div>
  );
}
