/**
 * CyberGuard AI — Login Page
 * ============================================================================
 * 
 * The primary authentication entry point.
 * 
 * Features:
 *   - Form validation using Zod + React Hook Form
 *   - Google Sign-In (OAuth SSO) integration
 *   - Self-service Account Recovery / Password Reset flow
 *   - Loading state on the submit button (prevents double-clicks)
 *   - Error toasts via Sonner
 *   - Role-based redirect on successful login
 *   - Password visibility toggle (built into the Input component)
 *   - Full dark mode support
 */

import React, { useState, useEffect } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { useNavigate, useLocation, Link } from "react-router-dom";
import { ShieldCheck, Mail, Lock, ArrowLeft, KeyRound, Sparkles } from "lucide-react";
import { toast } from "sonner";

import { useAuth } from "@/auth/AuthProvider";
import { api, tokenStore } from "@/lib/api";
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
  const [isGoogleLoading, setIsGoogleLoading] = useState(false);

  // Password Recovery Modal State
  const [showForgotModal, setShowForgotModal] = useState(false);
  const [resetEmail, setResetEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isResetting, setIsResetting] = useState(false);

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

  // Handle Google OAuth callback parameters on redirect
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const googleToken = params.get("google_token");
    const refreshToken = params.get("refresh_token");
    const error = params.get("error");

    if (error) {
      toast.error(decodeURIComponent(error));
    } else if (googleToken && refreshToken) {
      tokenStore.set(googleToken, refreshToken);
      toast.success("Welcome back! Signed in with Google.");
      navigate("/personal/dashboard", { replace: true });
    }
  }, [location.search, navigate]);

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
      toast.error(error.message || "Failed to log in");
    } finally {
      setIsSubmitting(false);
    }
  };

  // Google Sign-In Handler
  const handleGoogleSignIn = async () => {
    setIsGoogleLoading(true);
    try {
      const response = await api.get<{ auth_url: string }>("/auth/google/url");
      if (response.data.auth_url) {
        window.location.href = response.data.auth_url;
      }
    } catch (err: any) {
      const msg = err.response?.data?.detail || err.message || "Google Sign-In is currently unavailable";
      toast.info("Google Sign-In Setup", {
        description: "To activate Google Sign-In, set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your Render dashboard environment variables.",
      });
    } finally {
      setIsGoogleLoading(false);
    }
  };

  // One-Click Instant Demo Login
  const handleDemoLogin = async (demoEmail: string) => {
    setValue("email", demoEmail);
    setValue("password", "CyberGuard2026!");
    await onSubmit({ email: demoEmail, password: "CyberGuard2026!" });
  };

  // Password Recovery Submit
  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resetEmail) {
      toast.error("Please enter your account email address.");
      return;
    }
    if (newPassword.length < 8) {
      toast.error("Password must be at least 8 characters long.");
      return;
    }
    if (newPassword !== confirmPassword) {
      toast.error("New passwords do not match.");
      return;
    }

    setIsResetting(true);
    try {
      const res = await api.post("/auth/reset-password", {
        email: resetEmail,
        new_password: newPassword,
      });

      toast.success(res.data?.message || "Password updated successfully!");
      setValue("email", resetEmail);
      setShowForgotModal(false);
      setNewPassword("");
      setConfirmPassword("");
    } catch (err: any) {
      const detail = err.response?.data?.detail || err.message || "Failed to reset password";
      toast.error(detail);
    } finally {
      setIsResetting(false);
    }
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
            Sign in to your account to continue
          </p>
        </div>

        {/* ── Login Card ──────────────────────────────────────────────── */}
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm sm:p-8 dark:border-slate-800 dark:bg-slate-900">
          
          {/* ── One-Click Instant Demo Access ────────────────────────── */}
          <div className="mb-6 rounded-lg border border-cyan-500/30 bg-cyan-950/20 p-3.5 dark:border-cyan-500/25 dark:bg-cyan-950/30">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-cyan-400 flex items-center gap-1.5">
                <Sparkles size={14} className="text-cyan-400" />
                Instant 1-Click Demo Access
              </span>
              <span className="text-[10px] text-cyan-500/80 font-mono">Pre-seeded</span>
            </div>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => handleDemoLogin("analyst@cyberguard.ai")}
                disabled={isSubmitting}
                className="flex flex-col items-center justify-center rounded-md border border-cyan-500/40 bg-slate-900/80 px-2 py-2 text-xs font-medium text-slate-200 hover:border-cyan-400 hover:bg-cyan-950/50 hover:text-white transition shadow-sm"
              >
                <span className="font-semibold text-cyan-300">🛡️ Analyst</span>
                <span className="text-[10px] text-slate-400">SOC Portal</span>
              </button>
              <button
                type="button"
                onClick={() => handleDemoLogin("user@cyberguard.ai")}
                disabled={isSubmitting}
                className="flex flex-col items-center justify-center rounded-md border border-slate-700 bg-slate-900/80 px-2 py-2 text-xs font-medium text-slate-200 hover:border-cyan-400 hover:bg-cyan-950/50 hover:text-white transition shadow-sm"
              >
                <span className="font-semibold text-slate-200">👤 User</span>
                <span className="text-[10px] text-slate-400">Personal</span>
              </button>
              <button
                type="button"
                onClick={() => handleDemoLogin("admin@cyberguard.ai")}
                disabled={isSubmitting}
                className="flex flex-col items-center justify-center rounded-md border border-slate-700 bg-slate-900/80 px-2 py-2 text-xs font-medium text-slate-200 hover:border-cyan-400 hover:bg-cyan-950/50 hover:text-white transition shadow-sm"
              >
                <span className="font-semibold text-slate-200">🏢 Admin</span>
                <span className="text-[10px] text-slate-400">SecOps Org</span>
              </button>
            </div>
          </div>

          {/* ── Google SSO Button ──────────────────────────────────────── */}
          <button
            type="button"
            onClick={handleGoogleSignIn}
            disabled={isGoogleLoading}
            className="flex w-full items-center justify-center gap-3 rounded-lg border border-slate-300 bg-white px-4 py-2.5 text-sm font-semibold text-slate-700 shadow-sm transition hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
          >
            <svg className="h-4 w-4" viewBox="0 0 24 24">
              <path
                fill="#4285F4"
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              />
              <path
                fill="#34A853"
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              />
              <path
                fill="#FBBC05"
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
              />
              <path
                fill="#EA4335"
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
              />
            </svg>
            <span>{isGoogleLoading ? "Connecting to Google..." : "Continue with Google"}</span>
          </button>

          <div className="relative my-5">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-slate-200 dark:border-slate-800" />
            </div>
            <div className="relative flex justify-center text-xs uppercase">
              <span className="bg-white px-3 text-slate-500 dark:bg-slate-900 dark:text-slate-400">
                Or with email
              </span>
            </div>
          </div>

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            
            <Input
              label="Email"
              type="email"
              placeholder="you@company.com"
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
                  onClick={() => setShowForgotModal(true)}
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
              to="/select-account"
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

      {/* ── Password Recovery Modal ────────────────────────────────────── */}
      <Modal open={showForgotModal} onOpenChange={setShowForgotModal}>
        <ModalContent className="max-w-md">
          <ModalHeader>
            <div className="flex items-center gap-2 text-cyan-600 dark:text-cyan-400 mb-1">
              <KeyRound size={20} />
              <ModalTitle>Account Recovery</ModalTitle>
            </div>
            <ModalDescription>
              Enter your registered email and a new password to recover access to your account.
            </ModalDescription>
          </ModalHeader>

          <form onSubmit={handleResetPassword} className="space-y-4 py-2">
            <Input
              label="Account Email"
              type="email"
              placeholder="you@company.com"
              value={resetEmail}
              onChange={(e) => setResetEmail(e.target.value)}
              required
              leftIcon={<Mail size={16} />}
            />

            <Input
              label="New Password"
              type="password"
              placeholder="Minimum 8 characters"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
              leftIcon={<Lock size={16} />}
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
                isLoading={isResetting}
              >
                Reset Password
              </Button>
            </ModalFooter>
          </form>
        </ModalContent>
      </Modal>

    </div>
  );
}
