/**
 * CyberGuard AI — Pricing Page (/pricing)
 * ============================================================================
 * Transparent pricing models for Individuals, Analysts, and Organizations.
 */

import { useNavigate } from "react-router-dom";
import { Check, ShieldCheck, Zap, ArrowRight, Building2, User, Shield } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import PublicNavbar from "@/components/public/PublicNavbar";
import PublicFooter from "@/components/public/PublicFooter";
import { SEO } from "@/components/common/SEO";

const plans = [
  {
    name: "Individual",
    badge: "Free Forever",
    price: "$0",
    period: "per user / month",
    description: "Essential threat monitoring and phishing defense for personal laptops, workstations, and inboxes.",
    cta: "Start Free Protection",
    ctaRoute: "/register?type=individual",
    popular: false,
    features: [
      "Up to 5 personal endpoints monitored",
      "Gmail inbox scanning & EML threat analysis",
      "Access to AI Security Assistant",
      "Direct join private security rooms",
      "Community threat intelligence feeds",
      "Email alert notifications"
    ]
  },
  {
    name: "Security Analyst",
    badge: "Verified Practitioner",
    price: "Earn",
    period: "per investigated case",
    description: "Zero platform fee for verified practitioners. Receive payout per completed case and retainer.",
    cta: "Apply for Verification",
    ctaRoute: "/analyst/register",
    popular: true,
    features: [
      "Access to private Case Investigation Marketplace",
      "Full Forensic Evidence Vault access (SHA-256)",
      "Interactive AI Investigation Workbench",
      "Public verified analyst credential badge",
      "Integrated billing & automated direct payout",
      "Unlimited analyst case reports"
    ]
  },
  {
    name: "Organization",
    badge: "Enterprise Defense",
    price: "$199",
    period: "per month (base)",
    description: "Complete security orchestration for companies: fleet monitoring, private war rooms, and analyst retainers.",
    cta: "Create Organization",
    ctaRoute: "/organization/create",
    popular: false,
    features: [
      "Unlimited enterprise endpoints & log streams",
      "Private incident war rooms with passcode policy",
      "Hire & assign contracted security analysts",
      "Employee access governance & audit logging",
      "Advanced MITRE ATT&CK correlation engine",
      "Executive PDF & CSV compliance reports"
    ]
  }
];

export default function Pricing() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100 flex flex-col font-sans transition-colors">
      <SEO
        title="Predictable Cybersecurity Plans & Pricing — CyberGuard AI"
        description="Transparent security pricing: Free tier for individual device protection, competitive compensation for analysts, and scalable enterprise defense."
        canonicalPath="/pricing"
      />
      <PublicNavbar />

      <main className="flex-1 mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-12">
        <div className="text-center max-w-3xl mx-auto space-y-4 mb-16">
          <span className="text-xs font-bold uppercase tracking-wider text-cyan-600 dark:text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-3 py-1 rounded-full">
            Transparent Pricing
          </span>
          <h1 className="text-3xl sm:text-5xl font-black tracking-tight text-slate-900 dark:text-slate-100">
            Simple, Predictable Cybersecurity
          </h1>
          <p className="text-base sm:text-lg text-slate-600 dark:text-slate-400">
            No hidden fees. Individuals protect their devices for free, analysts get paid for their skills, and organizations get enterprise-grade defense.
          </p>
        </div>

        {/* Pricing Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-20">
          {plans.map((plan) => (
            <Card
              key={plan.name}
              className={`bg-white/80 dark:bg-slate-900/80 border transition-all duration-200 flex flex-col justify-between p-6 sm:p-8 relative ${
                plan.popular 
                  ? "border-cyan-500 shadow-lg shadow-cyan-500/10 dark:border-cyan-500" 
                  : "border-slate-200 dark:border-slate-800"
              }`}
            >
              {plan.popular && (
                <div className="absolute -top-3.5 left-1/2 -translate-x-1/2 bg-cyan-500 text-slate-950 text-[10px] font-black uppercase tracking-widest px-3 py-0.5 rounded-full shadow-md">
                  Most Popular
                </div>
              )}

              <div className="space-y-6">
                <div>
                  <div className="flex items-center justify-between">
                    <h2 className="text-xl font-black text-slate-900 dark:text-slate-100">
                      {plan.name}
                    </h2>
                    <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
                      {plan.badge}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">
                    {plan.description}
                  </p>
                </div>

                <div className="border-y border-slate-100 dark:border-slate-800 py-4">
                  <div className="flex items-baseline gap-1">
                    <span className="text-4xl font-black text-slate-900 dark:text-slate-100">
                      {plan.price}
                    </span>
                    <span className="text-xs text-slate-500 dark:text-slate-400">
                      / {plan.period}
                    </span>
                  </div>
                </div>

                <ul className="space-y-2.5">
                  {plan.features.map((feature, i) => (
                    <li key={i} className="flex items-start gap-2 text-xs text-slate-600 dark:text-slate-400">
                      <Check size={14} className="text-emerald-500 shrink-0 mt-0.5" />
                      <span>{feature}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="pt-8">
                <Button
                  size="md"
                  variant={plan.popular ? "primary" : "outline"}
                  onClick={() => navigate(plan.ctaRoute)}
                  className="w-full text-xs font-bold justify-center"
                >
                  {plan.cta} <ArrowRight size={14} className="ml-1.5" />
                </Button>
              </div>
            </Card>
          ))}
        </div>

        {/* Guarantee Banner */}
        <div className="rounded-2xl border border-slate-200 bg-white/70 p-6 sm:p-8 dark:border-slate-800 dark:bg-slate-900/70 text-center max-w-3xl mx-auto">
          <div className="flex items-center justify-center gap-2 mb-2 text-emerald-500 font-bold text-sm">
            <ShieldCheck size={20} />
            <span>Zero-Risk Guarantee</span>
          </div>
          <p className="text-xs text-slate-600 dark:text-slate-400">
            All data collection is opt-in, strictly encrypted (TLS 1.3 in-transit, AES-256 at-rest), and backed by complete audit logs. Export or purge your data at any time.
          </p>
        </div>
      </main>

      <PublicFooter />
    </div>
  );
}
