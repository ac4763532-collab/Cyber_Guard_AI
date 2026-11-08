/**
 * CyberGuard AI — Login Page
 * ============================================================================
 * 
 * The primary authentication entry point.
 * 
 * Features:
 *   - Form validation using Zod + React Hook Form
 *   - Loading state on the submit button (prevents double-clicks)
 *   - Error toasts via Sonner
 *   - Role-based redirect on successful login
 *   - Password visibility toggle (built into the Input component)
 *   - Full dark mode support
 */

import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { useNavigate, useLocation, Link } from "react-router-dom";
import { ShieldCheck, Mail, Lock, ArrowLeft } from "lucide-react";
import { toast } from "sonner";

import { useAuth } from "@/auth/AuthProvider";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";

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

  const {
    register,
    handleSubmit,
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
      toast.error(error.message || "Failed to log in");
    } finally {
      setIsSubmitting(false);
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
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
            
            <Input
              label="Email"
              type="email"
              placeholder="you@company.com"
              leftIcon={<Mail size={16} />}
              autoComplete="email"
              error={errors.email?.message}
              {...register("email")}
            />

            <Input
              label="Password"
              type="password"
              placeholder="••••••••"
              leftIcon={<Lock size={16} />}
              autoComplete="current-password"
              error={errors.password?.message}
              {...register("password")}
            />

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
    </div>
  );
}
