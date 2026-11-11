/**
 * CyberGuard AI — Strict 3-Step Registration Page
 * ============================================================================
 * 
 * Flow:
 *   Step 1: Account Details & Identity (Name, Email, Role, Password)
 *   Step 2: Email OTP Verification (6-Digit Security Code via Gmail/SMTP)
 *   Step 3: Workspace Confirmation & Account Activation
 */

import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { useNavigate, Link, useSearchParams } from "react-router-dom";
import { ShieldCheck, Mail, Lock, User, ArrowLeft, KeyRound, CheckCircle2, Shield, Briefcase, UserCheck } from "lucide-react";
import { toast } from "sonner";

import { useAuth } from "@/auth/AuthProvider";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";

const registerSchema = z
  .object({
    fullName: z.string().min(1, "Full name is required"),
    email: z
      .string()
      .min(1, "Email is required")
      .email("Please enter a valid email address"),
    password: z
      .string()
      .min(8, "Password must be at least 8 characters")
      .regex(/[a-zA-Z]/, "Password must contain at least one letter")
      .regex(/[0-9]/, "Password must contain at least one number"),
    confirmPassword: z.string().min(1, "Please confirm your password"),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Passwords do not match",
    path: ["confirmPassword"],
  });

type RegisterFormValues = z.infer<typeof registerSchema>;

export default function Register() {
  const { register: registerUser } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  // Wizard state: 1: Details -> 2: Email OTP -> 3: Activation
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [role, setRole] = useState<string>(searchParams.get("type") || "individual");
  const [verificationCode, setVerificationCode] = useState("");
  const [registrationToken, setRegistrationToken] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const {
    register,
    handleSubmit,
    getValues,
    formState: { errors },
  } = useForm<RegisterFormValues>({
    resolver: zodResolver(registerSchema),
    defaultValues: {
      fullName: "",
      email: "",
      password: "",
      confirmPassword: "",
    },
  });

  // Step 1: Submit Details & Request 6-Digit Email OTP
  const onInitiateRegistration = async (data: RegisterFormValues) => {
    setIsSubmitting(true);
    try {
      const res = await api.post("/auth/register/initiate", {
        email: data.email.trim().toLowerCase(),
        password: data.password,
        full_name: data.fullName.trim(),
        role: role,
      });

      toast.success(res.data?.message || "Verification code sent to your email!");
      setStep(2);
    } catch (error: any) {
      const msg = error.response?.data?.detail || error.response?.data?.error?.message || error.message || "Failed to initiate registration";
      toast.error(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  // Step 2: Verify 6-Digit Code
  const onVerifyCode = async (e: React.FormEvent) => {
    e.preventDefault();
    const email = getValues("email").trim().toLowerCase();
    if (!verificationCode || verificationCode.trim().length !== 6) {
      toast.error("Please enter the 6-digit verification code.");
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await api.post("/auth/register/verify-code", {
        email: email,
        code: verificationCode.trim(),
      });

      setRegistrationToken(res.data?.registration_token || "");
      toast.success("Email verified successfully!");
      setStep(3);
    } catch (error: any) {
      const msg = error.response?.data?.detail || error.response?.data?.error?.message || error.message || "Invalid verification code";
      toast.error(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  // Resend Verification Code
  const handleResendCode = async () => {
    const data = getValues();
    setIsSubmitting(true);
    try {
      const res = await api.post("/auth/register/initiate", {
        email: data.email.trim().toLowerCase(),
        password: data.password,
        full_name: data.fullName.trim(),
        role: role,
      });
      toast.success(res.data?.message || "A new code has been dispatched to your email.");
    } catch (error: any) {
      const msg = error.response?.data?.detail || error.message || "Failed to resend code";
      toast.error(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  // Step 3: Complete Registration & Enter Workspace
  const onCompleteRegistration = async () => {
    const data = getValues();
    setIsSubmitting(true);
    try {
      const registered = await registerUser(
        data.email.trim().toLowerCase(),
        data.password,
        data.fullName.trim(),
        role
      );

      toast.success("Account activated successfully! Welcome to CyberGuard AI.");

      const userRole = (registered?.role || role).toLowerCase();
      if (userRole === "analyst") {
        navigate("/analyst/dashboard", { replace: true });
      } else if (userRole === "organizer" || userRole === "org_admin" || userRole === "organization") {
        navigate("/organization/dashboard", { replace: true });
      } else {
        navigate("/personal/dashboard", { replace: true });
      }
    } catch (error: any) {
      const msg = error.response?.data?.detail || error.message || "Failed to complete registration";
      toast.error(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50 p-4 dark:bg-slate-950 font-sans">
      <div className="w-full max-w-lg">
        
        {/* ── Brand Header ────────────────────────────────────────────── */}
        <div className="mb-6 flex flex-col items-center text-center">
          <Link
            to="/"
            className="flex h-12 w-12 items-center justify-center rounded-xl bg-brand-100 text-brand-600 dark:bg-brand-900/50 dark:text-brand-400 hover:scale-105 transition-transform shadow-md"
            title="Back to Home"
          >
            <ShieldCheck size={28} />
          </Link>
          <h1 className="mt-4 text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Create your account
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Strict 3-step security verification onboarding
          </p>
        </div>

        {/* ── Wizard Progress Bar ──────────────────────────────────────── */}
        <div className="mb-6 rounded-xl border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900 shadow-sm">
          <div className="flex items-center justify-between text-xs">
            <div className={`flex items-center gap-1.5 font-medium ${step >= 1 ? "text-cyan-500 font-semibold" : "text-slate-400"}`}>
              <span className={`flex h-5 w-5 items-center justify-center rounded-full text-[11px] ${step >= 1 ? "bg-cyan-500 text-white" : "bg-slate-200 dark:bg-slate-800 text-slate-400"}`}>
                1
              </span>
              <span>Account Setup</span>
            </div>
            <span className="text-slate-300 dark:text-slate-700">&rarr;</span>
            <div className={`flex items-center gap-1.5 font-medium ${step >= 2 ? "text-cyan-500 font-semibold" : "text-slate-400"}`}>
              <span className={`flex h-5 w-5 items-center justify-center rounded-full text-[11px] ${step >= 2 ? "bg-cyan-500 text-white" : "bg-slate-200 dark:bg-slate-800 text-slate-400"}`}>
                2
              </span>
              <span>Verify Email</span>
            </div>
            <span className="text-slate-300 dark:text-slate-700">&rarr;</span>
            <div className={`flex items-center gap-1.5 font-medium ${step >= 3 ? "text-cyan-500 font-semibold" : "text-slate-400"}`}>
              <span className={`flex h-5 w-5 items-center justify-center rounded-full text-[11px] ${step >= 3 ? "bg-cyan-500 text-white" : "bg-slate-200 dark:bg-slate-800 text-slate-400"}`}>
                3
              </span>
              <span>Activation</span>
            </div>
          </div>
        </div>

        {/* ── Wizard Card ─────────────────────────────────────────────── */}
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm sm:p-8 dark:border-slate-800 dark:bg-slate-900">
          
          {/* ── STEP 1: Details & Persona ─────────────────────────────── */}
          {step === 1 && (
            <form onSubmit={handleSubmit(onInitiateRegistration)} className="space-y-4">
              
              <Input
                label="Full Name"
                type="text"
                placeholder="Priya Sharma"
                leftIcon={<User size={16} />}
                autoComplete="name"
                error={errors.fullName?.message}
                {...register("fullName")}
              />

              <Input
                label="Corporate or Personal Email"
                type="email"
                placeholder="priya@company.com"
                leftIcon={<Mail size={16} />}
                autoComplete="email"
                error={errors.email?.message}
                {...register("email")}
              />

              {/* Persona / Role Selector */}
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                  Select Security Persona
                </label>
                <div className="grid grid-cols-3 gap-2">
                  <button
                    type="button"
                    onClick={() => setRole("individual")}
                    className={`flex flex-col items-center justify-center p-3 rounded-lg border text-xs text-center transition ${
                      role === "individual"
                        ? "border-cyan-500 bg-cyan-950/30 text-cyan-300"
                        : "border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-slate-400 hover:border-slate-300"
                    }`}
                  >
                    <UserCheck size={18} className="mb-1 text-cyan-400" />
                    <span className="font-semibold text-slate-200">Personal</span>
                    <span className="text-[10px] text-slate-500">Security</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setRole("analyst")}
                    className={`flex flex-col items-center justify-center p-3 rounded-lg border text-xs text-center transition ${
                      role === "analyst"
                        ? "border-cyan-500 bg-cyan-950/30 text-cyan-300"
                        : "border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-slate-400 hover:border-slate-300"
                    }`}
                  >
                    <Shield size={18} className="mb-1 text-cyan-400" />
                    <span className="font-semibold text-slate-200">SOC Analyst</span>
                    <span className="text-[10px] text-slate-500">Incident Triage</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setRole("organizer")}
                    className={`flex flex-col items-center justify-center p-3 rounded-lg border text-xs text-center transition ${
                      role === "organizer"
                        ? "border-cyan-500 bg-cyan-950/30 text-cyan-300"
                        : "border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-slate-400 hover:border-slate-300"
                    }`}
                  >
                    <Briefcase size={18} className="mb-1 text-cyan-400" />
                    <span className="font-semibold text-slate-200">SecOps Org</span>
                    <span className="text-[10px] text-slate-500">Enterprise</span>
                  </button>
                </div>
              </div>

              <Input
                label="Password"
                type="password"
                placeholder="••••••••"
                leftIcon={<Lock size={16} />}
                autoComplete="new-password"
                error={errors.password?.message}
                helperText="At least 8 characters with both letters and numbers."
                {...register("password")}
              />

              <Input
                label="Confirm Password"
                type="password"
                placeholder="••••••••"
                leftIcon={<Lock size={16} />}
                autoComplete="new-password"
                error={errors.confirmPassword?.message}
                {...register("confirmPassword")}
              />

              <Button
                type="submit"
                className="w-full mt-4"
                size="lg"
                isLoading={isSubmitting}
              >
                Continue to Verification &rarr;
              </Button>
            </form>
          )}

          {/* ── STEP 2: Verify 6-Digit Email Code ─────────────────────── */}
          {step === 2 && (
            <form onSubmit={onVerifyCode} className="space-y-4">
              <div className="text-center py-2">
                <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-cyan-500/10 text-cyan-400 mb-2">
                  <KeyRound size={24} />
                </div>
                <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                  Verify your email
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  We dispatched a 6-digit verification code to <span className="font-semibold text-cyan-400">{getValues("email")}</span>.
                </p>
              </div>

              <div>
                <label className="block text-center text-xs font-medium text-slate-400 mb-1.5 uppercase tracking-wider">
                  Enter 6-Digit Code
                </label>
                <input
                  type="text"
                  maxLength={6}
                  placeholder="000000"
                  value={verificationCode}
                  onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, ""))}
                  autoFocus
                  required
                  className="w-full text-center text-3xl font-mono tracking-widest px-4 py-3 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
                <p className="mt-1 text-center text-[11px] text-slate-400">
                  Code expires in 15 minutes. Check your spam folder if delayed.
                </p>
              </div>

              <div className="flex justify-between items-center text-xs pt-1">
                <button
                  type="button"
                  onClick={() => setStep(1)}
                  className="text-slate-400 hover:text-slate-200"
                >
                  &larr; Change email or role
                </button>
                <button
                  type="button"
                  onClick={handleResendCode}
                  disabled={isSubmitting}
                  className="text-cyan-500 hover:underline font-medium"
                >
                  Resend code
                </button>
              </div>

              <Button
                type="submit"
                className="w-full mt-3"
                size="lg"
                isLoading={isSubmitting}
              >
                Verify Code &rarr;
              </Button>
            </form>
          )}

          {/* ── STEP 3: Workspace Confirmation & Activation ──────────── */}
          {step === 3 && (
            <div className="space-y-5">
              <div className="flex items-center gap-3 p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                <CheckCircle2 size={24} className="flex-shrink-0" />
                <div>
                  <p className="text-sm font-semibold">Email Verified Successfully!</p>
                  <p className="text-xs text-emerald-500/80">Account ownership verified for {getValues("email")}.</p>
                </div>
              </div>

              <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 p-4 space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-slate-400">Account Holder:</span>
                  <span className="font-semibold text-slate-200">{getValues("fullName")}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Verified Email:</span>
                  <span className="font-semibold text-slate-200">{getValues("email")}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Security Persona:</span>
                  <span className="font-semibold text-cyan-400 uppercase tracking-wider">{role}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Dedicated Workspace:</span>
                  <span className="font-semibold text-slate-200">Auto-provisioned</span>
                </div>
              </div>

              <Button
                type="button"
                onClick={onCompleteRegistration}
                className="w-full"
                size="lg"
                isLoading={isSubmitting}
              >
                Complete Registration &amp; Enter Workspace &rarr;
              </Button>
            </div>
          )}

          {/* ── Footer Links ────────────────────────────────────────── */}
          <div className="mt-6 text-center text-sm border-t border-slate-100 dark:border-slate-800 pt-4">
            <span className="text-slate-500 dark:text-slate-400">
              Already have an account?{" "}
            </span>
            <Link
              to="/login"
              className="font-semibold text-brand-600 hover:text-brand-500 dark:text-brand-400 dark:hover:text-brand-300"
            >
              Sign in
            </Link>
          </div>
        </div>

        {/* ── Terms Disclaimer ──────────────────────────────────────── */}
        <p className="mt-4 text-center text-xs text-slate-400 dark:text-slate-500">
          By registering, you agree to our{" "}
          <Link to="/terms" className="underline hover:text-cyan-400">Terms of Service</Link>{" "}
          and{" "}
          <Link to="/privacy" className="underline hover:text-cyan-400">Privacy Policy</Link>.
        </p>

        <div className="mt-3 text-center">
          <Link to="/" className="inline-flex items-center gap-1.5 text-xs text-slate-500 hover:text-cyan-500 transition-colors">
            <ArrowLeft size={14} /> Back to Homepage
          </Link>
        </div>

      </div>
    </div>
  );
}
