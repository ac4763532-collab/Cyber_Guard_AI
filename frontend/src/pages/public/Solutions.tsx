/**
 * CyberGuard AI — Solutions Page (/solutions)
 * ============================================================================
 * Outlines the three role-tailored security experiences:
 * 1. Individual & Personal Device Security
 * 2. Independent Security Analyst Operations
 * 3. Enterprise Organization Defense & Room Management
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { 
  User, 
  Shield, 
  Building2, 
  CheckCircle, 
  ArrowRight, 
  Server, 
  Mail, 
  Terminal, 
  Briefcase, 
  Users, 
  DoorOpen 
} from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import PublicNavbar from "@/components/public/PublicNavbar";
import PublicFooter from "@/components/public/PublicFooter";
import { cn } from "@/lib/utils";

const solutions = [
  {
    id: "individual",
    badge: "Personal Security",
    title: "For Individuals & Normal Users",
    description: "Guard your personal workstations, laptops, and Gmail inbox from credential stuffing, malware payloads, and targeted phishing scams.",
    cta: "Start Free Personal Protection",
    ctaRoute: "/register?type=individual",
    icon: <User className="w-8 h-8 text-cyan-400" />,
    features: [
      "Device health & telemetry monitoring (Windows, Linux, macOS)",
      "Gmail EML upload & automated SPF/DKIM/DMARC phishing verification",
      "Interactive AI Security Assistant for personal threat guidance",
      "Direct join private security rooms hosted by your employer or security analyst",
      "Zero configuration required: up and running in minutes"
    ]
  },
  {
    id: "analyst",
    badge: "Analyst Portal",
    title: "For Independent Security Analysts",
    description: "Monetize your threat hunting skills. Accept verified security cases, examine digital forensic evidence, and submit incident remediation reports.",
    cta: "Apply as a Verified Analyst",
    ctaRoute: "/analyst/register",
    icon: <Shield className="w-8 h-8 text-emerald-400" />,
    features: [
      "Exclusive case marketplace with transparent compensation",
      "Chain-of-custody Evidence Vault with SHA-256 artifact verification",
      "Interactive AI Investigation Workbench for deep forensic correlation",
      "Public Analyst Profile with verified credentials and customer reviews",
      "Automated case billing and direct payment tracking"
    ]
  },
  {
    id: "organization",
    badge: "Enterprise Defense",
    title: "For Companies & Organizations",
    description: "Comprehensive multi-tenant security operations: fleet device monitoring, corporate war rooms, employee governance, and verified analyst retainer.",
    cta: "Create Organization Workspace",
    ctaRoute: "/organization/create",
    icon: <Building2 className="w-8 h-8 text-indigo-400" />,
    features: [
      "Unified enterprise fleet monitoring across departments",
      "Collaborative incident war rooms with role-based member permissions",
      "Contract and invite verified external analysts to active incidents",
      "Employee management with granular access controls and audit logging",
      "Executive compliance and threat posture reporting"
    ]
  }
];

export default function Solutions() {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState("all");

  const displayedSolutions = activeTab === "all" 
    ? solutions 
    : solutions.filter(s => s.id === activeTab);

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100 flex flex-col font-sans">
      <PublicNavbar />

      <main className="flex-1 mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-12">
        {/* Header */}
        <div className="text-center max-w-3xl mx-auto space-y-4 mb-12">
          <span className="text-xs font-bold uppercase tracking-wider text-cyan-600 dark:text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-3 py-1 rounded-full">
            Tailored Security Solutions
          </span>
          <h1 className="text-3xl sm:text-5xl font-black tracking-tight text-slate-900 dark:text-slate-100">
            A Specialized Experience for Every Security Stakeholder
          </h1>
          <p className="text-base sm:text-lg text-slate-600 dark:text-slate-400">
            CyberGuard AI replaces one-size-fits-all tools with three specialized workspace models designed specifically for individuals, professional analysts, and organizations.
          </p>

          {/* Filter Pills */}
          <div className="flex flex-wrap items-center justify-center gap-2 pt-4">
            <button
              onClick={() => setActiveTab("all")}
              className={cn(
                "px-4 py-2 text-xs font-bold rounded-lg transition",
                activeTab === "all"
                  ? "bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20"
                  : "bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-300 hover:bg-slate-300 dark:hover:bg-slate-700"
              )}
            >
              All Solutions
            </button>
            <button
              onClick={() => setActiveTab("individual")}
              className={cn(
                "px-4 py-2 text-xs font-bold rounded-lg transition",
                activeTab === "individual"
                  ? "bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20"
                  : "bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-300 hover:bg-slate-300 dark:hover:bg-slate-700"
              )}
            >
              Individuals
            </button>
            <button
              onClick={() => setActiveTab("analyst")}
              className={cn(
                "px-4 py-2 text-xs font-bold rounded-lg transition",
                activeTab === "analyst"
                  ? "bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20"
                  : "bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-300 hover:bg-slate-300 dark:hover:bg-slate-700"
              )}
            >
              Security Analysts
            </button>
            <button
              onClick={() => setActiveTab("organization")}
              className={cn(
                "px-4 py-2 text-xs font-bold rounded-lg transition",
                activeTab === "organization"
                  ? "bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20"
                  : "bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-300 hover:bg-slate-300 dark:hover:bg-slate-700"
              )}
            >
              Organizations
            </button>
          </div>
        </div>

        {/* Solutions Cards */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-16">
          {displayedSolutions.map((sol) => (
            <Card
              key={sol.id}
              className="bg-white/80 dark:bg-slate-900/80 border-slate-200 dark:border-slate-800 hover:border-cyan-500/40 transition-all duration-200 flex flex-col justify-between p-6 sm:p-8"
            >
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <div className="p-3 rounded-2xl bg-slate-100 dark:bg-slate-800">
                    {sol.icon}
                  </div>
                  <span className="text-[11px] font-bold uppercase tracking-wider px-2.5 py-1 rounded-full bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/20">
                    {sol.badge}
                  </span>
                </div>

                <div>
                  <h2 className="text-xl font-black text-slate-900 dark:text-slate-100">
                    {sol.title}
                  </h2>
                  <p className="text-xs text-slate-600 dark:text-slate-400 mt-2 leading-relaxed">
                    {sol.description}
                  </p>
                </div>

                <div className="space-y-2 pt-4 border-t border-slate-100 dark:border-slate-800">
                  <p className="text-xs font-bold text-slate-900 dark:text-slate-200 uppercase tracking-wider">
                    Included Capabilities:
                  </p>
                  <ul className="space-y-2">
                    {sol.features.map((feat, i) => (
                      <li key={i} className="flex items-start gap-2 text-xs text-slate-600 dark:text-slate-400">
                        <CheckCircle size={14} className="text-emerald-500 shrink-0 mt-0.5" />
                        <span>{feat}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              <div className="pt-8">
                <Button
                  size="md"
                  variant="primary"
                  onClick={() => navigate(sol.ctaRoute)}
                  className="w-full text-xs font-bold justify-center"
                >
                  {sol.cta} <ArrowRight size={14} className="ml-1.5" />
                </Button>
              </div>
            </Card>
          ))}
        </div>

        {/* Global CTA */}
        <div className="text-center py-6">
          <p className="text-xs text-slate-500">
            Unsure which account fits your requirements?{" "}
            <button
              onClick={() => navigate("/select-account")}
              className="text-cyan-500 hover:underline font-bold"
            >
              Use the Account Selection Wizard &rarr;
            </button>
          </p>
        </div>
      </main>

      <PublicFooter />
    </div>
  );
}
