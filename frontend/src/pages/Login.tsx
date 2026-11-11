/**
 * CyberGuard AI — Login Page
 * ============================================================================
 * 
 * Strict Enterprise Authentication:
 *   - Form validation using Zod + React Hook Form
 *   - Secure Email + Password authentication
 *   - Multi-step 2FA-verified Account Recovery (Email OTP verification code via Gmail/SMTP)
 *   - Rate-limiting & lockout-aware error handling
 *   - Full dark mode support
 */

import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { useNavigate, useLocation, Link } from "react-router-dom";
import { ShieldCheck, Mail, Lock, ArrowLeft, KeyRound, CheckCircle2 } from "lucide-react";
import { toast } from "sonner";

import { useAuth } from "@/auth/AuthProvider";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import {
  Modal,
  ModalContent,
  ModalHeader,
  ModalTitle,
  ModalDescription,
  ModalFooter,
} from "@/components/ui/Modal";

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

  // Multi-step Password Recovery State (Email -> 6-Digit Code -> New Password)
  const [showForgotModal, setShowForgotModal] = useState(false);
  const [recoveryStep, setRecoveryStep] = useState<1 | 2 | 3>(1);
  const [recoveryEmail, setRecoveryEmail] = useState("");
  const [verificationCode, setVerificationCode] = useState("");
  const [resetToken, setResetToken] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isRecoveryLoading, setIsRecoveryLoading] = useState(false);
  const [devRecoveryCode, setDevRecoveryCode] = useState<string | null>(null);

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
      const loggedInUser = await login(data.email, data.password);
      toast.success("Welcome back!");

      // If bounced here with a specific destination, return there
      if (location.state?.from?.pathname && location.state.from.pathname !== "/login" && location.state.from.pathname !== "/dashboard") {
        navigate(location.state.from.pathname, { replace: true });
        return;
      }

      // Otherwise, navigate directly to authorized role-based workspace
      const role = (loggedInUser?.role || "individual").toLowerCase();
      if (role === "analyst") {
        navigate("/analyst/dashboard", { replace: true });
      } else if (role === "organizer" || role === "org_admin" || role === "organization") {
        navigate("/organization/dashboard", { replace: true });
      } else {
        navigate("/personal/dashboard", { replace: true });
      }
    } catch (error: any) {
      toast.error(error.message || "Invalid email or password.");
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
      if (res.data?.preview_code) {
        setDevRecoveryCode(res.data.preview_code);
        toast.info(res.data?.dev_hint || "Test recovery code shown on screen.", { duration: 7000 });
      } else {
        setDevRecoveryCode(null);
        toast.success(res.data?.message || "Verification code sent to your email!");
      }
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
      // Reset modal state
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
        <div className="mb-8 flex flex-col items-center text-center">
          <Link
            to="/"
            className="flex h-12 w-12 items-center justify-center rounded-xl bg-brand-100 text-brand-600 dark:bg-brand-900/50 dark:text-brand-400 hover:scale-105 transition-transform shadow-md"
            title="Back to Home"
          >
            <ShieldCheck size={28} />
          </Link>
          <h1 className="mt-4 text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Welcome to CyberGuard
          </h1>
          <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
            Sign in to your security operations account
          </p>
        </div>

        {/* ── Login Card ──────────────────────────────────────────────── */}
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm sm:p-8 dark:border-slate-800 dark:bg-slate-900">
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            
            <Input
              label="Email"
              type="email"
              placeholder="operator@company.com"
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
              className="w-full mt-2"
              size="lg"
              isLoading={isSubmitting}
            >
              Sign In
            </Button>
          </form>

          {/* ── Footer Links ────────────────────────────────────────────── */}
          <div className="mt-6 text-center text-sm">
            <span className="text-slate-500 dark:text-slate-400">
              Don't have an account?{" "}
            </span>
            <Link
              to="/register"
              className="font-semibold text-brand-600 hover:text-brand-500 dark:text-brand-400 dark:hover:text-brand-300"
            >
              Get started
            </Link>
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
                label="Registered Account Email"
                type="email"
                placeholder="operator@company.com"
                value={recoveryEmail}
                onChange={(e) => setRecoveryEmail(e.target.value)}
                required
                leftIcon={<Mail size={16} />}
              />
              <ModalFooter className="mt-6">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setShowForgotModal(false)}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  isLoading={isRecoveryLoading}
                >
                  Send Verification Code
                </Button>
              </ModalFooter>
            </form>
          )}

          {/* ── Step 2: Verify 6-Digit Code ──────────────────────────── */}
          {recoveryStep === 2 && (
            <form onSubmit={handleVerifyCode} className="space-y-4 py-2">
              {devRecoveryCode && (
                <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-xl text-xs space-y-1.5 text-slate-300">
                  <div className="flex items-center gap-1.5 text-amber-400 font-bold">
                    <span>⚠️ SMTP Not Configured on Render</span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    To deliver real emails to your Gmail inbox, configure SMTP in Render settings. Meanwhile, your test code is:
                  </p>
                  <div className="flex items-center justify-between pt-1">
                    <span className="font-mono text-xl font-black text-amber-300 tracking-widest">{devRecoveryCode}</span>
                    <button
                      type="button"
                      onClick={() => setVerificationCode(devRecoveryCode)}
                      className="px-2.5 py-1 bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 rounded font-semibold text-[11px]"
                    >
                      Auto-fill Code
                    </button>
                  </div>
                </div>
              )}
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                  6-Digit Verification Code
                </label>
                <input
                  type="text"
                  maxLength={6}
                  placeholder="000000"
                  value={verificationCode}
                  onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, ""))}
                  required
                  className="w-full text-center text-2xl font-mono tracking-widest px-4 py-3 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
                <p className="mt-1.5 text-xs text-slate-400">
                  Check your inbox for the code. Valid for 15 minutes.
                </p>
              </div>

              <div className="flex justify-between items-center text-xs">
                <button
                  type="button"
                  onClick={() => setRecoveryStep(1)}
                  className="text-slate-500 hover:text-slate-700 dark:hover:text-slate-300"
                >
                  Change email
                </button>
                <button
                  type="button"
                  onClick={handleSendCode}
                  disabled={isRecoveryLoading}
                  className="text-cyan-500 hover:underline font-medium"
                >
                  Resend code
                </button>
              </div>

              <ModalFooter className="mt-6">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setShowForgotModal(false)}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  isLoading={isRecoveryLoading}
                >
                  Verify Code
                </Button>
              </ModalFooter>
            </form>
          )}

          {/* ── Step 3: Enter New Password ──────────────────────────── */}
          {recoveryStep === 3 && (
            <form onSubmit={handleResetPassword} className="space-y-4 py-2">
              <div className="flex items-center gap-2 p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs">
                <CheckCircle2 size={16} />
                <span>Identity verified for {recoveryEmail}</span>
              </div>

              <Input
                label="New Password"
                type="password"
                placeholder="Minimum 8 characters"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
                leftIcon={<Lock size={16} />}
                helperText="At least 8 characters with letters and numbers."
              />

              <Input
                label="Confirm New Password"
                type="password"
                placeholder="Re-enter new password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                leftIcon={<Lock size={16} />}
              />

              <ModalFooter className="mt-6">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setShowForgotModal(false)}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  isLoading={isRecoveryLoading}
                >
                  Update Password
                </Button>
              </ModalFooter>
            </form>
          )}

        </ModalContent>
      </Modal>

    </div>
  );
}
