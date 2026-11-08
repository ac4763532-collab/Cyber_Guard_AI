/**
 * CyberGuard AI — Login Page
 * ============================================================================
 * 
 * The primary authentication entry point.
 * 
 * Features:
 *   - Form validation using Zod + React Hook Form
 *   - Loading state on the submit button (prevents double-clicks)
 *   - Error toasts via Sonner (e.g., "Invalid credentials", "Account locked")
 *   - Smart redirect: if the user was kicked out of a protected route,
 *     logs them in and sends them right back to where they were going.
 *   - Password visibility toggle (built into the Input component)
 *   - Full dark mode support
 */

import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { useNavigate, useLocation, Link } from "react-router-dom";
import { ShieldCheck, Mail, Lock } from "lucide-react";
import { toast } from "sonner";

import { useAuth } from "@/auth/AuthProvider";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";


// ============================================================================
// VALIDATION SCHEMA
// ============================================================================
// Mirrors the backend's LoginRequest schema (File 41).
// We don't enforce min length on the password here because the backend
// needs to return the specific "Invalid credentials" error for wrong passwords.

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


// ============================================================================
// COMPONENT
// ============================================================================

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Where to redirect after login? 
  // If we were bounced here by ProtectedRoute, it saved the original
  // destination in `location.state.from`. Otherwise, go to dashboard.
  const from = location.state?.from?.pathname || "/dashboard";

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
      await login(data.email, data.password);
      
      // If successful, navigate to the original destination
      toast.success("Welcome back!");
      navigate(from, { replace: true });
    } catch (error: any) {
      // The `login()` function in AuthProvider throws a normalized Error
      toast.error(error.message || "Failed to log in");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50 p-4 dark:bg-slate-950">
      <div className="w-full max-w-md">
        
        {/* ── Brand Header ────────────────────────────────────────────── */}
        <div className="mb-8 flex flex-col items-center text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-brand-100 text-brand-600 dark:bg-brand-900/50 dark:text-brand-400">
            <ShieldCheck size={28} />
          </div>
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
              to="/register"
              className="font-semibold text-brand-600 hover:text-brand-500 dark:text-brand-400 dark:hover:text-brand-300"
            >
              Sign up
            </Link>
          </div>
        </div>

      </div>
    </div>
  );
}