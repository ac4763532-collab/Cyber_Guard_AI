/**
 * CyberGuard AI — User Selection (Page 2)
 * ============================================================================
 *
 * Public page where new visitors select their account type before proceeding
 * to their workspace-specific dashboard. Exactly three selectable cards:
 * Individual, Security Analyst, Organization. One selected at a time.
 * Visual cyan border/glow/check when selected. Continue disabled until
 * terms checkbox is accepted.
 *
 * Flow: Individual → /personal/dashboard (5)
 *       Analyst  → /analyst/register (21)
 *       Organization → /organization/create (37)
 *
 * Design: dark navy (#071321) background with cyan/blue accents, Inter font,
 * responsive grid, cyan border/glow/check on selection, disabled Continue
 * until terms accepted.
 */

import { useState } from "react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle, CardDescription } from "@/components/ui/Card";
import { cn } from "@/lib/utils";

interface AccountCardProps {
  label: string;
  href: string;
  description: string;
  variant: "individual" | "analyst" | "organization";
}

const accountCards: AccountCardProps[] = [
  {
    label: "Individual",
    href: "/personal/dashboard",
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
]

import { useNavigate } from "react-router-dom";

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
    <main className="min-h-screen bg-slate-50 dark:bg-slate-950">
      <div className="max-w-7xl mx-auto p-4 sm:p-6 sm:py-12">
        <div className="text-center mb-12">
          <h2 className="text-4xl sm:text-5xl font-bold tracking-tight text-slate-900 dark:text-slate-100 mb-4">
            Welcome to CyberGuard AI
          </h2>
          <p className="text-slate-600 dark:text-slate-400 text-lg max-w-md mx-auto">
            Select your account type to get started with the right security
            experience for your needs.
          </p>
        </div>

        {/* ── Selection Cards ───────────────────────────────────────── */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {accountCards.map((card, i) => (
            <Card
              key={card.label}
              className={cn(
                "border rounded-lg p-6 transition-all duration-200 cursor-pointer",
                selected?.variant === card.variant
                  ? "border-[var(--cyan)] shadow-cyan-500/20"
                  : "border-slate-300 dark:border-slate-700 hover:border-slate-400 dark:hover:border-slate-600",
                selected?.index === i && "ring-2 ring-cyan-500/20"
              )}
              onClick={() => handleSelect(card.variant, i, card.href)}
            >
              <CardHeader>
                <CardTitle className="text-xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
                  {card.label}
                </CardTitle>
              </CardHeader>
              <CardDescription className="text-sm text-slate-500 dark:text-slate-400 mt-2">
                {card.description}
              </CardDescription>
            </Card>
          ))}
        </div>

        {/* ── Selected state visual feedback ──────────────────────────── */}
        {selected && (
          <div className="mt-8 p-6 rounded-lg bg-cyan-500/5 text-center">
            <svg
              className="w-12 h-12 mx-auto text-cyan-400 mb-3"
              viewBox="0 0 24 24"
              fill="currentColor"
            >
              <path d="M9 12l2 2 4-4m6.3-2.8a7.96 7.96 0 0 1-1.8 6.4 8.05 8.05 0 0 1-5.3 0 7.93 7.93 0 0 1-1.8-6.4c0-1.1.4-2.1 1.2-3L12 6l-1.2-1.2c.8-.8 1.2-2.1 1.2-3 0-3.3-2.5-6-5.6-6a9.96 9.96 0 0 0-4 5.4 9.98 9.98 0 0 0 4.6 2.4zM12 3a3 3 0 1 0 0 6 3 3 0 0 0 0-6z" />
            </svg>
            <p className="text-cyan-200 font-medium">
              {selected.variant} selected
            </p>
            <p className="text-cyan-100 text-sm mt-1">
              Continue to {selected.href}
            </p>
          </div>
        )}

        {/* ── Continue button ─────────────────────────────────────────── */}
        <div className="mt-10 pt-8 border-t border-slate-200 dark:border-slate-800">
          <Button
            variant="primary"
            size="lg"
            disabled={continueDisabled}
            className="w-full"
            onClick={handleContinue}
          >
            {continueDisabled
              ? "Complete terms to continue"
              : selected?.variant === "individual"
              ? "Continue to Personal Security"
              : selected?.variant === "analyst"
              ? "Continue to Security Analyst"
              : "Continue to Organization"}
          </Button>
        </div>

        {/* ── Terms checkbox ──────────────────────────────────────────── */}
        <div className="mt-6 text-sm">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={termsAccepted}
              onChange={(e) => setTermsAccepted(e.target.checked)}
              className="rounded border-slate-500 dark:border-slate-400 focus:ring-sky-500"
            />
            I agree to the <a href="/terms" className="underline text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 transition-colors">Terms of Service</a> and
            <a href="/privacy" className="underline text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 transition-colors">Privacy Policy</a>.
          </label>
        </div>
      </div>
    </main>
  );
}