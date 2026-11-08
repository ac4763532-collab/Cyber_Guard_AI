/**
 * CyberGuard AI — Registration Page
 * ============================================================================
 * 
 * Handles new user sign-ups.
 * 
 * Key differences from Login:
 *   1. **Password Complexity** — Enforces the backend's rules (min 8 chars,
 *      at least one letter, at least one number) using Zod.
 *   2. **Confirm Password** — Uses Zod `.refine()` to ensure both passwords match.
 *   3. **Pending Verification UX** — The backend creates accounts in a
 *      `PENDING_VERIFICATION` state. We show a toast after registration
 *      explaining they need to verify their email to unlock full access.
 */

import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { useNavigate, Link } from "react-router-dom";
import { ShieldCheck, Mail, Lock, User } from "lucide-react";
import { toast } from "sonner";

import { useAuth } from "@/auth/AuthProvider";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";


// ============================================================================
// VALIDATION SCHEMA
// ============================================================================
// Mirrors the backend's RegisterRequest schema (File 41).

const registerSchema = z
  .object({
    fullName: z.string().optional(),
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
    path: ["confirmPassword"], // Tells Zod to attach the error to the confirmPassword field
  });

type RegisterFormValues = z.infer<typeof registerSchema>;


// ============================================================================
// COMPONENT
// ============================================================================

export default function Register() {
  const { register: registerUser } = useAuth();
  const navigate = useNavigate();
  const [isSubmitting, setIsSubmitting] = useState(false);

  const {
    register,
    handleSubmit,
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

  const onSubmit = async (data: RegisterFormValues) => {
    setIsSubmitting(true);
    try {
      await registerUser(data.email, data.password, data.fullName);
      
      toast.success("Account created successfully!", {
        description: "Please check your email to verify your account.",
        duration: 6000, // Show slightly longer so they can read the instruction
      });
      
      navigate("/dashboard", { replace: true });
    } catch (error: any) {
      toast.error(error.message || "Failed to create account");
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
            Create your account
          </h1>
          <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
            Start monitoring your security in minutes
          </p>
        </div>

        {/* ── Register Card ───────────────────────────────────────────── */}
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm sm:p-8 dark:border-slate-800 dark:bg-slate-900">
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            
            <Input
              label="Full Name"
              type="text"
              placeholder="Jane Doe"
              leftIcon={<User size={16} />}
              autoComplete="name"
              error={errors.fullName?.message}
              {...register("fullName")}
            />

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
              autoComplete="new-password"
              error={errors.password?.message}
              helperText="At least 8 characters, including a letter and a number."
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
              className="w-full mt-2"
              size="lg"
              isLoading={isSubmitting}
            >
              Create Account
            </Button>
          </form>

          {/* ── Footer Links ────────────────────────────────────────────── */}
          <div className="mt-6 text-center text-sm">
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

        {/* ── Terms Disclaimer ────────────────────────────────────────── */}
        <p className="mt-8 text-center text-xs text-slate-400 dark:text-slate-500">
          By signing up, you agree to our Terms of Service and Privacy Policy.
        </p>

      </div>
    </div>
  );
}