/**
 * CyberGuard AI — Login Page with Role-Based Workspace Portals
 * ============================================================================
 * 
 * Strict Enterprise Authentication:
 *   - Dedicated Role & Workspace Selector: Individual, Security Analyst, Organization
 *   - Direct routing to role-specific authorized dashboards
 *   - Multi-step 2FA-verified Account Recovery (Email OTP verification code via Gmail/SMTP)
 *   - Form validation using Zod + React Hook Form
 *   - Full dark mode support
 */

import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { useNavigate, useLocation, Link } from "react-router-dom";
import { 
  ShieldCheck, 
  Mail, 
  Lock, 
  ArrowLeft, 
  KeyRound, 
  Laptop, 
  ShieldAlert, 
  Building2, 
  CheckCircle2,
  ArrowRight
} from "lucide-react";
import { toast } from "sonner";

import { useAuth } from "@/auth/AuthProvider";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { cn } from "@/lib/utils";
import {
  Modal,
  ModalContent,
  ModalHeader,
  ModalTitle,
  ModalDescription,
} from "@/components/ui/Modal";

type PortalType = "individual" | "analyst" | "organizer";

interface PortalConfig {
  id: PortalType;
  title: string;
  badge: string;
  description: string;
  destination: string;
  icon: React.ReactNode;
  activeColor: string;
  activeBorder: string;
  activeBg: string;
  badgeClass: string;
  buttonText: string;
  registerText: string;
  registerLink: string;
}

const PORTALS: Record<PortalType, PortalConfig> = {
  individual: {
    id: "individual",
    title: "Individual",
    badge: "Personal Defense",
    description: "Monitor personal computers, Gmail threat security, active processes, and logs.",
    destination: "/personal/dashboard",
    icon: <Laptop size={18} />,
    activeColor: "text-cyan-400",
    activeBorder: "border-cyan-500",
    activeBg: "bg-cyan-500/10",
    badgeClass: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
    buttonText: "Sign In to Personal Protection",
    registerText: "Create a Personal Account",
    registerLink: "/register?type=individual",
  },
  analyst: {
    id: "analyst",
    title: "Security Analyst",
    badge: "SOC Operations",
    description: "Case investigation workbench, evidence library, threat hunting & advisory.",
    destination: "/analyst/dashboard",
    icon: <ShieldAlert size={18} />,
    activeColor: "text-emerald-400",
    activeBorder: "border-emerald-500",
    activeBg: "bg-emerald-500/10",
    badgeClass: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    buttonText: "Sign In to Analyst SOC",
    registerText: "Apply as a Verified Security Analyst",
    registerLink: "/analyst/register",
  },
  organizer: {
    id: "organizer",
    title: "Organization",
    badge: "Enterprise Console",
    description: "Company infrastructure, department rooms, employee telemetry & security teams.",
    destination: "/organization/dashboard",
    icon: <Building2 size={18} />,
    activeColor: "text-blue-400",
    activeBorder: "border-blue-500",
    activeBg: "bg-blue-500/10",
    badgeClass: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    buttonText: "Sign In to Organization Console",
    registerText: "Create an Organization Workspace",
    registerLink: "/organization/create",
  },
};

const loginSchema = z.object({
  email: z
    .string()
    .min(1, "Email is required")
    .email("Please enter a valid email address"),
  password: z
    .string()
    .min(1, "Password is required"),
});

type LoginFormValues = z.infer<typeof loginSchema>;

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Parse portal from URL parameters if passed (e.g. /login?portal=analyst)
  const searchParams = new URLSearchParams(location.search);
  const initialPortalParam = (
    searchParams.get("portal") ||
    searchParams.get("role") ||
    searchParams.get("type") ||
    "individual"
  ).toLowerCase();

  const initialPortal: PortalType = 
    initialPortalParam === "analyst" 
      ? "analyst" 
      : (initialPortalParam === "organizer" || initialPortalParam === "organization")
      ? "organizer"
      : "individual";

  const [selectedPortal, setSelectedPortal] = useState<PortalType>(initialPortal);
  const currentPortal = PORTALS[selectedPortal];

  // Multi-step Password Recovery State (Email -> 6-Digit Code -> New Password)
  const [showForgotModal, setShowForgotModal] = useState(false);
  const [recoveryStep, setRecoveryStep] = useState<1 | 2 | 3>(1);
  const [recoveryEmail, setRecoveryEmail] = useState("");
  const [verificationCode, setVerificationCode] = useState("");
  const [resetToken, setResetToken] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isRecoveryLoading, setIsRecoveryLoading] = useState(false);

  const {
    register,
    handleSubmit,
    setValue,
    formState: { errors },
  } = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      email: "",
      password: "",
    },
  });

  const onSubmit = async (data: LoginFormValues) => {
    setIsSubmitting(true);
    try {
      const loggedInUser = await login(data.email, data.password, selectedPortal);
      toast.success(`Welcome back to CyberGuard!`);

      const effectiveRole = (loggedInUser?.role || selectedPortal || "individual").toLowerCase();

      // Route directly based on user's authorized role and selected portal
      if (selectedPortal === "analyst" || effectiveRole === "analyst") {
        navigate("/analyst/dashboard", { replace: true });
      } else if (selectedPortal === "organizer" || effectiveRole === "organizer" || effectiveRole === "org_admin") {
        navigate("/organization/dashboard", { replace: true });
      } else {
        // If bounced here with a specific valid personal return destination, honor it
        const fromPath = location.state?.from?.pathname;
        if (fromPath && fromPath.startsWith("/personal/")) {
          navigate(fromPath, { replace: true });
        } else {
          navigate("/personal/dashboard", { replace: true });
        }
      }
    } catch (error: any) {
      const detail = error?.response?.data?.detail;
      const msg = typeof detail === "string" 
        ? detail 
        : (Array.isArray(detail) && detail[0]?.msg 
            ? detail[0].msg 
            : (error?.response?.data?.error?.message || error?.message || "Invalid email or password."));
      toast.error(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  // Step 1: Send 6-Digit Verification Code to Email
  const handleSendCode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!recoveryEmail || !recoveryEmail.includes("@")) {
      toast.error("Please enter a valid email address.");
      return;
    }

    setIsRecoveryLoading(true);
    try {
      const res = await api.post("/auth/forgot-password", {
        email: recoveryEmail.trim().toLowerCase(),
      });
      toast.success(res.data?.message || "Verification code sent to your email!");
      setRecoveryStep(2);
    } catch (err: any) {
      const detail = err.response?.data?.detail || err.response?.data?.error?.message || err.message || "Failed to send code";
      toast.error(detail);
    } finally {
      setIsRecoveryLoading(false);
    }
  };

  // Step 2: Verify the 6-Digit Code
  const handleVerifyCode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!verificationCode || verificationCode.trim().length !== 6) {
      toast.error("Please enter the 6-digit verification code.");
      return;
    }

    setIsRecoveryLoading(true);
    try {
      const res = await api.post("/auth/verify-reset-code", {
        email: recoveryEmail.trim().toLowerCase(),
        code: verificationCode.trim(),
      });
      setResetToken(res.data?.reset_token || "");
      toast.success("Code verified successfully! Please set your new password.");
      setRecoveryStep(3);
    } catch (err: any) {
      const detail = err.response?.data?.detail || err.response?.data?.error?.message || err.message || "Invalid code";
      toast.error(detail);
    } finally {
      setIsRecoveryLoading(false);
    }
  };

  // Step 3: Set and Confirm New Password
  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPassword.length < 8) {
      toast.error("Password must be at least 8 characters long.");
      return;
    }
    if (!/[a-zA-Z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
      toast.error("Password must contain both letters and numbers.");
      return;
    }
    if (newPassword !== confirmPassword) {
      toast.error("Passwords do not match.");
      return;
    }

    setIsRecoveryLoading(true);
    try {
      const res = await api.post("/auth/reset-password", {
        email: recoveryEmail.trim().toLowerCase(),
        reset_token: resetToken,
        code: verificationCode.trim(),
        new_password: newPassword,
      });

      toast.success(res.data?.message || "Password updated successfully! You can now log in.");
      setValue("email", recoveryEmail);
      setShowForgotModal(false);
      setRecoveryStep(1);
      setRecoveryEmail("");
      setVerificationCode("");
      setResetToken("");
      setNewPassword("");
      setConfirmPassword("");
    } catch (err: any) {
      const detail = err.response?.data?.detail || err.response?.data?.error?.message || err.message || "Failed to reset password";
      toast.error(detail);
    } finally {
      setIsRecoveryLoading(false);
    }
  };

  const handleOpenForgotModal = () => {
    setRecoveryStep(1);
    setVerificationCode("");
    setResetToken("");
    setNewPassword("");
    setConfirmPassword("");
    setShowForgotModal(true);
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50 p-4 dark:bg-slate-950 font-sans">
      <div className="w-full max-w-md">
        
        {/* ── Brand Header ────────────────────────────────────────────── */}
        <div className="mb-6 flex flex-col items-center text-center">
          <Link
            to="/"
            className="flex h-12 w-12 items-center justify-center rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:scale-105 transition-transform shadow-md shadow-cyan-500/20"
            title="Back to Home"
          >
            <ShieldCheck size={28} />
          </Link>
          <h1 className="mt-4 text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Welcome to CyberGuard
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Select your workspace portal and sign in to your dashboard
          </p>
        </div>

        {/* ── Portal Switcher Tabs ────────────────────────────────────── */}
        <div className="mb-4 rounded-xl border border-slate-200 bg-white p-1.5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 px-2 py-1 flex items-center justify-between">
            <span>Select Dashboard Portal</span>
            <span className="text-[10px] text-cyan-400 font-mono lowercase">role-authenticated</span>
          </div>
          <div className="grid grid-cols-3 gap-1.5 mt-1">
            {(Object.values(PORTALS) as PortalConfig[]).map((portal) => {
              const isSelected = selectedPortal === portal.id;
              return (
                <button
                  key={portal.id}
                  type="button"
                  onClick={() => setSelectedPortal(portal.id)}
                  className={cn(
                    "flex flex-col items-center justify-center gap-1.5 py-2.5 px-2 rounded-lg text-xs font-medium transition-all cursor-pointer",
                    isSelected
                      ? `${portal.activeBg} ${portal.activeBorder} ${portal.activeColor} border shadow-sm font-bold`
                      : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent"
                  )}
                >
                  <div className="w-5 h-5 flex items-center justify-center">
                    {portal.icon}
                  </div>
                  <span className="leading-tight text-center">{portal.title}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* ── Login Card ──────────────────────────────────────────────── */}
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm sm:p-7 dark:border-slate-800 dark:bg-slate-900">
          
          {/* Active Portal Header Banner */}
          <div className="mb-5 p-3 rounded-lg bg-slate-950/80 border border-slate-800 flex items-start gap-3">
            <div className={cn("p-2 rounded-md bg-slate-900 border border-slate-800 shrink-0", currentPortal.activeColor)}>
              {currentPortal.icon}
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-bold text-slate-100">{currentPortal.title} Portal</span>
                <span className={cn("text-[10px] font-mono px-2 py-0.5 rounded-full border", currentPortal.badgeClass)}>
                  {currentPortal.badge}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                {currentPortal.description}
              </p>
              <div className="mt-2 text-[10px] text-slate-500 font-mono flex items-center gap-1">
                <span>Direct Destination:</span>
                <span className="text-cyan-400 font-semibold">{currentPortal.destination}</span>
              </div>
            </div>
          </div>

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            
            <Input
              label="Account Email"
              type="email"
              placeholder={selectedPortal === "analyst" ? "analyst@soc.company.com" : selectedPortal === "organizer" ? "admin@enterprise.com" : "you@example.com"}
              leftIcon={<Mail size={16} />}
              autoComplete="email"
              error={errors.email?.message}
              {...register("email")}
            />

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-sm font-medium text-slate-700 dark:text-slate-300">
                  Password
                </label>
                <button
                  type="button"
                  onClick={handleOpenForgotModal}
                  className="text-xs font-semibold text-cyan-600 hover:text-cyan-500 dark:text-cyan-400 dark:hover:text-cyan-300 transition-colors"
                >
                  Forgot password?
                </button>
              </div>
              <Input
                type="password"
                placeholder="••••••••"
                leftIcon={<Lock size={16} />}
                autoComplete="current-password"
                error={errors.password?.message}
                {...register("password")}
              />
            </div>

            <Button
              type="submit"
              className="w-full mt-2 font-semibold"
              size="lg"
              isLoading={isSubmitting}
            >
              {currentPortal.buttonText}
            </Button>
          </form>

          {/* ── Footer Dynamic Role Links ───────────────────────────────── */}
          <div className="mt-6 pt-5 border-t border-slate-100 dark:border-slate-800/80 space-y-3 text-center text-sm">
            <div className="text-xs text-slate-400">
              Need a new {currentPortal.title.toLowerCase()} account?{" "}
              <Link
                to={currentPortal.registerLink}
                className="font-semibold text-cyan-400 hover:text-cyan-300 underline underline-offset-2 ml-1"
              >
                {currentPortal.registerText}
              </Link>
            </div>

            <div className="text-xs text-slate-500 flex items-center justify-center gap-1.5 pt-1">
              <span>Looking for other accounts?</span>
              <Link
                to="/select-account"
                className="text-slate-400 hover:text-cyan-400 transition-colors inline-flex items-center gap-1 font-medium"
              >
                Choose Account Type <ArrowRight size={12} />
              </Link>
            </div>
          </div>
        </div>

        <div className="mt-6 text-center">
          <Link to="/" className="inline-flex items-center gap-1.5 text-xs text-slate-500 hover:text-cyan-500 transition-colors">
            <ArrowLeft size={14} /> Back to Homepage
          </Link>
        </div>

      </div>

      {/* ── Multi-Step Password Recovery Modal ────────────────────────── */}
      <Modal open={showForgotModal} onOpenChange={setShowForgotModal}>
        <ModalContent className="max-w-md">
          <ModalHeader>
            <div className="flex items-center gap-2 text-cyan-600 dark:text-cyan-400 mb-1">
              <KeyRound size={20} />
              <ModalTitle>Account Security Recovery</ModalTitle>
            </div>
            <ModalDescription>
              {recoveryStep === 1 && "Enter your registered email address to receive a secure 6-digit verification code."}
              {recoveryStep === 2 && `Enter the 6-digit verification code sent to ${recoveryEmail}.`}
              {recoveryStep === 3 && "Code verified! Enter your new password below."}
            </ModalDescription>
          </ModalHeader>

          {/* ── Progress Indicators ──────────────────────────────────── */}
          <div className="flex items-center justify-between px-2 py-1 text-xs text-slate-400 border-b border-slate-100 dark:border-slate-800 mb-4">
            <span className={recoveryStep >= 1 ? "font-semibold text-cyan-500" : ""}>1. Email</span>
            <span>&rarr;</span>
            <span className={recoveryStep >= 2 ? "font-semibold text-cyan-500" : ""}>2. Verify Code</span>
            <span>&rarr;</span>
            <span className={recoveryStep >= 3 ? "font-semibold text-cyan-500" : ""}>3. Reset</span>
          </div>

          {/* ── Step 1: Send Code ────────────────────────────────────── */}
          {recoveryStep === 1 && (
            <form onSubmit={handleSendCode} className="space-y-4 py-2">
              <Input
                label="Registered Email"
                type="email"
                placeholder="operator@company.com"
                value={recoveryEmail}
                onChange={(e) => setRecoveryEmail(e.target.value)}
                leftIcon={<Mail size={16} />}
                autoComplete="email"
                required
              />
              <Button type="submit" className="w-full" isLoading={isRecoveryLoading}>
                Send 6-Digit Code
              </Button>
            </form>
          )}

          {/* ── Step 2: Verify Code ──────────────────────────────────── */}
          {recoveryStep === 2 && (
            <form onSubmit={handleVerifyCode} className="space-y-4 py-2">
              <div className="text-center p-3 bg-slate-50 dark:bg-slate-900 rounded-lg border border-slate-200 dark:border-slate-800 mb-2">
                <p className="text-xs text-slate-500 dark:text-slate-400">A 6-digit OTP code was sent to:</p>
                <p className="font-mono text-sm font-bold text-cyan-600 dark:text-cyan-400 mt-0.5">{recoveryEmail}</p>
              </div>
              <Input
                label="6-Digit Verification Code"
                type="text"
                placeholder="123456"
                value={verificationCode}
                onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                leftIcon={<KeyRound size={16} />}
                maxLength={6}
                required
              />
              <div className="flex gap-2">
                <Button type="button" variant="outline" className="w-1/3" onClick={() => setRecoveryStep(1)}>
                  Back
                </Button>
                <Button type="submit" className="w-2/3" isLoading={isRecoveryLoading}>
                  Verify Code
                </Button>
              </div>
            </form>
          )}

          {/* ── Step 3: New Password ─────────────────────────────────── */}
          {recoveryStep === 3 && (
            <form onSubmit={handleResetPassword} className="space-y-4 py-2">
              <Input
                label="New Password"
                type="password"
                placeholder="Min 8 chars with letters & numbers"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                leftIcon={<Lock size={16} />}
                required
              />
              <Input
                label="Confirm New Password"
                type="password"
                placeholder="••••••••"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                leftIcon={<CheckCircle2 size={16} />}
                required
              />
              <Button type="submit" className="w-full" isLoading={isRecoveryLoading}>
                Update Password & Log In
              </Button>
            </form>
          )}
        </ModalContent>
      </Modal>
    </div>
  );
}
