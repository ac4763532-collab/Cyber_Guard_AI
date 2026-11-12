/**
 * CyberGuard AI — User Selection (Page 2)
 * ============================================================================
 * Public page where visitors select their account type before proceeding
 * to their workspace-specific registration or setup.
 *
 * Flow: Individual   → /register?type=individual
 *       Analyst      → /analyst/register
 *       Organization → /organization/create
 */

import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowLeft, Check, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardDescription } from "@/components/ui/Card";
import { cn } from "@/lib/utils";
import PublicNavbar from "@/components/public/PublicNavbar";
import PublicFooter from "@/components/public/PublicFooter";
import { SEO } from "@/components/common/SEO";

interface AccountCardProps {
  label: string;
  href: string;
  description: string;
  variant: "individual" | "analyst" | "organization";
}

const accountCards: AccountCardProps[] = [
  {
    label: "Individual",
    href: "/register?type=individual",
    description:
      "Protect your personal devices, monitor email activity, and analyze logs and network traffic for suspicious behavior.",
    variant: "individual",
  },
  {
    label: "Security Analyst",
    href: "/analyst/register",
    description:
      "Professional investigation services with case management, analyst verification and AI-assisted analysis.",
    variant: "analyst",
  },
  {
    label: "Organization",
    href: "/organization/create",
    description:
      "Cybersecurity management for companies. Create organizations, manage departments, invite and manage analysts.",
    variant: "organization",
  },
];

export default function UserSelection() {
  const navigate = useNavigate();
  const [selected, setSelected] = useState<{ variant: string; index: number; href: string } | null>(null);
  const [termsAccepted, setTermsAccepted] = useState(false);

  const handleSelect = (variant: string, index: number, href: string) => {
    setSelected({ variant, index, href });
  };

  const handleContinue = () => {
    if (selected && termsAccepted) {
      navigate(selected.href);
    }
  };

  const continueDisabled = !selected || !termsAccepted;

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100 flex flex-col font-sans transition-colors">
      <SEO
        title="Select Account Workspace — CyberGuard AI"
        description="Select your CyberGuard AI account type: Individual Protection, Verified Security Analyst, or Enterprise Organization."
        canonicalPath="/select-account"
      />
      <PublicNavbar />

      <main className="flex-1 mx-auto max-w-5xl px-4 sm:px-6 lg:px-8 py-10">
        
        <div className="mb-6">
          <Link
            to="/"
            className="inline-flex items-center gap-1.5 text-xs text-slate-500 hover:text-cyan-500 transition-colors"
          >
            <ArrowLeft size={14} /> Back to Homepage
          </Link>
        </div>

        <div className="text-center mb-10 space-y-2">
          <h1 className="text-3xl sm:text-4xl font-black tracking-tight text-slate-900 dark:text-slate-100">
            Select Your Account Type
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-400 max-w-md mx-auto">
            Choose the workspace that aligns with your security responsibilities.
          </p>
        </div>

        {/* ── Selection Cards ───────────────────────────────────────── */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          {accountCards.map((card, i) => (
            <Card
              key={card.label}
              className={cn(
                "border rounded-xl p-6 transition-all duration-200 cursor-pointer bg-white dark:bg-slate-900 flex flex-col justify-between",
                selected?.variant === card.variant
                  ? "border-cyan-500 ring-2 ring-cyan-500/30 shadow-lg shadow-cyan-500/10"
                  : "border-slate-200 dark:border-slate-800 hover:border-slate-400 dark:hover:border-slate-700"
              )}
              onClick={() => handleSelect(card.variant, i, card.href)}
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider text-cyan-600 dark:text-cyan-400">
                    Step 1 of 2
                  </span>
                  {selected?.variant === card.variant && (
                    <span className="flex h-5 w-5 items-center justify-center rounded-full bg-cyan-500 text-slate-950">
                      <Check size={12} strokeWidth={3} />
                    </span>
                  )}
                </div>

                <CardTitle className="text-xl font-bold text-slate-900 dark:text-slate-100">
                  {card.label}
                </CardTitle>

                <CardDescription className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                  {card.description}
                </CardDescription>
              </div>

              <div className="pt-6">
                <Button
                  size="sm"
                  variant={selected?.variant === card.variant ? "primary" : "outline"}
                  onClick={() => handleSelect(card.variant, i, card.href)}
                  className="w-full text-xs font-bold"
                >
                  {selected?.variant === card.variant ? "Selected" : "Select Role"}
                </Button>
              </div>
            </Card>
          ))}
        </div>

        {/* ── Terms and Continue ────────────────────────────────────── */}
        <div className="max-w-md mx-auto bg-white/60 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-4">
          <label className="flex items-start gap-3 cursor-pointer text-xs text-slate-600 dark:text-slate-400">
            <input
              type="checkbox"
              checked={termsAccepted}
              onChange={(e) => setTermsAccepted(e.target.checked)}
              className="mt-0.5 rounded border-slate-400 text-cyan-500 focus:ring-cyan-500"
            />
            <span>
              I agree to the{" "}
              <Link to="/terms" className="text-cyan-600 dark:text-cyan-400 font-bold hover:underline">
                Terms of Service
              </Link>{" "}
              and{" "}
              <Link to="/privacy" className="text-cyan-600 dark:text-cyan-400 font-bold hover:underline">
                Privacy Policy
              </Link>
              .
            </span>
          </label>

          <Button
            variant="primary"
            size="lg"
            disabled={continueDisabled}
            className="w-full text-sm font-bold shadow-md shadow-cyan-500/20"
            onClick={handleContinue}
          >
            {continueDisabled
              ? "Accept terms to continue"
              : selected?.variant === "individual"
              ? "Continue to Individual Sign Up"
              : selected?.variant === "analyst"
              ? "Continue to Analyst Application"
              : "Continue to Organization Setup"}
          </Button>

          <p className="text-center text-xs text-slate-500">
            Already have an account?{" "}
            <Link to="/login" className="text-cyan-600 dark:text-cyan-400 font-bold hover:underline">
              Sign In
            </Link>
          </p>
        </div>
      </main>

      <PublicFooter />
    </div>
  );
}
