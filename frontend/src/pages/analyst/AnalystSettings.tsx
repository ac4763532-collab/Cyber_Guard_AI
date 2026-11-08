/**
 * CyberGuard AI — Page 36: Analyst Settings & Security Preferences
 * ============================================================================
 * Configure notification thresholds, MFA security, payout credentials,
 * API keys, and SLA auto-acceptance rules.
 */

import { useState } from "react";
import { 
  Shield, 
  Key, 
  Bell, 
  DollarSign, 
  Lock, 
  Save, 
  CheckCircle2, 
  AlertTriangle,
  Smartphone,
  Eye,
  EyeOff
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { useAuth } from "@/auth/AuthProvider";
import { toast } from "sonner";

export default function AnalystSettings() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState<"general" | "payout" | "security" | "notifications">("general");
  const [saved, setSaved] = useState(false);

  // Form states
  const [payoutMethod, setPayoutMethod] = useState("bank_transfer");
  const [bankAccount, setBankAccount] = useState("**** **** **** 8821");
  const [routingNumber, setRoutingNumber] = useState("121000358");
  const [emailAlerts, setEmailAlerts] = useState(true);
  const [criticalSms, setCriticalSms] = useState(true);
  const [autoAcceptSla, setAutoAcceptSla] = useState(false);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSaved(true);
    toast.success("Analyst settings updated successfully.");
    setTimeout(() => setSaved(false), 3000);
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded-full">
            Page 36 • Analyst Workspace
          </span>
          <h1 className="text-3xl font-black text-slate-100 tracking-tight mt-2">
            Analyst Preferences & Settings
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Manage your payout methods, two-factor authentication, and triage alerts.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {saved && (
            <span className="text-xs text-emerald-400 flex items-center gap-1 font-semibold">
              <CheckCircle2 className="w-4 h-4" /> Changes saved
            </span>
          )}
          <Button onClick={handleSave} className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs">
            <Save className="w-4 h-4 mr-1.5" /> Save Preferences
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-slate-800 pb-3">
        {[
          { id: "general", label: "General & SLA", icon: Shield },
          { id: "payout", label: "Payout Details", icon: DollarSign },
          { id: "security", label: "Security & MFA", icon: Lock },
          { id: "notifications", label: "Incident Alerts", icon: Bell },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
                isActive
                  ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
              }`}
            >
              <Icon className="w-4 h-4" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Tab Content */}
      {activeTab === "general" && (
        <Card className="border-slate-800 bg-slate-900/60">
          <CardHeader>
            <CardTitle className="text-slate-200 text-base">Triage & Operational SLAs</CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="flex items-center justify-between p-4 rounded-xl bg-slate-950 border border-slate-800">
              <div>
                <p className="text-sm font-semibold text-slate-200">Auto-Accept Urgent Incidents</p>
                <p className="text-xs text-slate-400 mt-0.5">Automatically lock cases assigned to you with a critical P1 SLA window.</p>
              </div>
              <input
                type="checkbox"
                checked={autoAcceptSla}
                onChange={(e) => setAutoAcceptSla(e.target.checked)}
                className="w-4 h-4 rounded bg-slate-800 border-slate-700 text-emerald-500 focus:ring-emerald-500"
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">Standard Response Time Target</label>
                <select className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500">
                  <option>Under 15 minutes (High Priority Tier)</option>
                  <option>Under 1 hour (Standard Tier)</option>
                  <option>Under 4 hours (Extended Tier)</option>
                </select>
              </div>
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">Max Concurrent Active Cases</label>
                <input
                  type="number"
                  defaultValue={5}
                  min={1}
                  max={20}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500"
                />
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {activeTab === "payout" && (
        <Card className="border-slate-800 bg-slate-900/60">
          <CardHeader>
            <CardTitle className="text-slate-200 text-base">Escrow & Milestone Payout Setup</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">Payout Method</label>
                <select 
                  value={payoutMethod}
                  onChange={(e) => setPayoutMethod(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500"
                >
                  <option value="bank_transfer">ACH / Direct Bank Wire</option>
                  <option value="stripe">Stripe Connect Account</option>
                  <option value="crypto_usdc">USDC (Arbitrum / Polygon)</option>
                </select>
              </div>
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">Account Number / IBAN</label>
                <input
                  type="text"
                  value={bankAccount}
                  onChange={(e) => setBankAccount(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500"
                />
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {activeTab === "security" && (
        <Card className="border-slate-800 bg-slate-900/60">
          <CardHeader>
            <CardTitle className="text-slate-200 text-base">Analyst Authentication & Hardware Keys</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between p-4 rounded-xl bg-slate-950 border border-slate-800">
              <div className="flex items-center gap-3">
                <Smartphone className="w-5 h-5 text-emerald-400" />
                <div>
                  <p className="text-sm font-semibold text-slate-200">TOTP Two-Factor Authentication</p>
                  <p className="text-xs text-slate-400">Enforce 6-digit authenticator code on every case decryption session.</p>
                </div>
              </div>
              <span className="px-2.5 py-1 text-xs font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 rounded-md">
                Active
              </span>
            </div>
          </CardContent>
        </Card>
      )}

      {activeTab === "notifications" && (
        <Card className="border-slate-800 bg-slate-900/60">
          <CardHeader>
            <CardTitle className="text-slate-200 text-base">Urgent Escalation Channels</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between p-4 rounded-xl bg-slate-950 border border-slate-800">
              <div>
                <p className="text-sm font-semibold text-slate-200">Email Notifications on New Case Assignments</p>
                <p className="text-xs text-slate-400">Receive instant dispatch summaries when assigned by client or org admin.</p>
              </div>
              <input
                type="checkbox"
                checked={emailAlerts}
                onChange={(e) => setEmailAlerts(e.target.checked)}
                className="w-4 h-4 rounded bg-slate-800 border-slate-700 text-emerald-500 focus:ring-emerald-500"
              />
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
