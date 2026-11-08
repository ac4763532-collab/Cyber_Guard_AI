/**
 * CyberGuard AI — Analyst Registration (Page 21)
 * ============================================================================
 *
 * Registration page for Security Analysts to join the platform.
 * Requires verification before they can offer services.
 *
 * Flow from Page 2: UserSelection → /analyst/register
 *
 * Design: dark navy (#071321) background with cyan/blue accents, Inter font,
 * multi-step form with validation, verification requirements clearly shown.
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, UserCheck, FileText, Mail, Lock, Eye, EyeOff, ChevronRight, CheckCircle, AlertCircle, Loader2 } from "lucide-react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { toast } from "sonner";

import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardContent } from "@/components/ui/Card";
import { cn } from "@/lib/utils";

const analystSchema = z.object({
  // Step 1: Account Info
  email: z.string().email("Invalid email address"),
  password: z.string().min(12, "Password must be at least 12 characters")
    .regex(/[A-Z]/, "Must contain at least one uppercase letter")
    .regex(/[a-z]/, "Must contain at least one lowercase letter")
    .regex(/[0-9]/, "Must contain at least one number")
    .regex(/[^A-Za-z0-9]/, "Must contain at least one special character"),
  confirmPassword: z.string(),
  fullName: z.string().min(2, "Full name is required"),
  // Step 2: Professional Info
  title: z.string().min(2, "Professional title is required"),
  company: z.string().optional(),
  yearsExperience: z.coerce.number().min(0).max(50),
  specializations: z.array(z.string()).min(1, "Select at least one specialization"),
  certifications: z.string().optional(),
  bio: z.string().max(500, "Bio must be 500 characters or less").optional(),
  // Step 3: Verification
  verificationDoc: z.any().optional(), // File upload
  agreeToTerms: z.boolean().refine(val => val === true, "You must agree to the terms"),
}).refine(data => data.password === data.confirmPassword, {
  message: "Passwords do not match",
  path: ["confirmPassword"],
});

type AnalystFormValues = z.infer<typeof analystSchema>;

const SPECIALIZATIONS = [
  "Incident Response",
  "Threat Hunting",
  "Malware Analysis",
  "Digital Forensics",
  "Vulnerability Assessment",
  "Penetration Testing",
  "Security Architecture",
  "Compliance & Audit",
  "Cloud Security",
  "Network Security",
  "Application Security",
  "Email Security",
];

const STEPS = [
  { id: 1, label: "Account", description: "Create your account credentials" },
  { id: 2, label: "Profile", description: "Professional information & expertise" },
  { id: 3, label: "Verification", description: "Submit verification documents" },
];

export default function AnalystRegister() {
  const navigate = useNavigate();
  const [currentStep, setCurrentStep] = useState(1);
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [verificationFile, setVerificationFile] = useState<File | null>(null);

  const form = useForm<AnalystFormValues>({
    resolver: zodResolver(analystSchema),
    defaultValues: {
      email: "",
      password: "",
      confirmPassword: "",
      fullName: "",
      title: "",
      company: "",
      yearsExperience: 0,
      specializations: [],
      certifications: "",
      bio: "",
      agreeToTerms: false,
    },
    mode: "onBlur",
  });

  const watchSpecializations = form.watch("specializations");

  const handleSpecializationChange = (spec: string) => {
    const current = watchSpecializations || [];
    if (current.includes(spec)) {
      form.setValue("specializations", current.filter(s => s !== spec));
    } else {
      form.setValue("specializations", [...current, spec]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      // Validate file type and size
      const validTypes = ["application/pdf", "image/jpeg", "image/png"];
      const maxSize = 10 * 1024 * 1024; // 10MB

      if (!validTypes.includes(file.type)) {
        toast.error("Please upload a PDF, JPG, or PNG file");
        return;
      }
      if (file.size > maxSize) {
        toast.error("File must be less than 10MB");
        return;
      }
      setVerificationFile(file);
      form.setValue("verificationDoc", file);
    }
  };

  const nextStep = () => {
    const stepFields: Record<number, (keyof AnalystFormValues)[]> = {
      1: ["email", "password", "confirmPassword", "fullName"],
      2: ["title", "yearsExperience", "specializations"],
      3: ["agreeToTerms"],
    };

    const fieldsToValidate = stepFields[currentStep] || [];

    // Trigger validation for all fields in current step
    form.trigger(fieldsToValidate).then(isValid => {
      if (isValid) {
        if (currentStep < 3) {
          setCurrentStep(currentStep + 1);
        }
      }
    });
  };

  const prevStep = () => {
    if (currentStep > 1) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleSubmit = async (_values: AnalystFormValues) => {
    setIsSubmitting(true);

    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 2000));

      toast.success("Registration submitted! Verification typically takes 24-48 hours.");
      navigate("/select-account");
    } catch (error) {
      toast.error("Registration failed. Please try again.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const getStepStatus = (step: number) => {
    if (step < currentStep) return "completed";
    if (step === currentStep) return "active";
    return "pending";
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex items-center justify-center py-12 px-4">
      <div className="w-full max-w-3xl">
        {/* ── Header ─────────────────────────────────────────────────────── */}
        <div className="text-center mb-8">
          <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-brand-500/10 flex items-center justify-center">
            <Shield className="w-8 h-8 text-brand-500" />
          </div>
          <h1 className="text-3xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Security Analyst Registration
          </h1>
          <p className="mt-2 text-slate-500 dark:text-slate-400">
            Join our network of verified security professionals
          </p>
        </div>

        {/* ── Progress Steps ─────────────────────────────────────────────── */}
        <div className="mb-8">
          <div className="relative">
            <div className="absolute top-3 left-0 right-0 h-1 bg-slate-200 dark:bg-slate-700" />
            {STEPS.map((step, _index) => (
              <div key={step.id} className="relative flex items-center justify-center">
                <div className={cn(
                  "w-6 h-6 rounded-full border-2 flex items-center justify-center z-10 transition-all",
                  getStepStatus(step.id) === "completed"
                    ? "bg-brand-500 border-brand-500 text-white"
                    : getStepStatus(step.id) === "active"
                    ? "border-brand-500 text-brand-500 bg-white dark:bg-slate-900"
                    : "border-slate-300 dark:border-slate-600 text-slate-400 bg-white dark:bg-slate-900"
                )}>
                  {getStepStatus(step.id) === "completed" ? (
                    <CheckCircle className="w-4 h-4" />
                  ) : (
                    <span className="text-sm font-bold">{step.id}</span>
                  )}
                </div>
                <div className="mt-2 text-center w-32 px-2">
                  <p className={cn(
                    "text-sm font-medium",
                    getStepStatus(step.id) === "active"
                      ? "text-brand-500"
                      : getStepStatus(step.id) === "completed"
                      ? "text-brand-500"
                      : "text-slate-500 dark:text-slate-400"
                  )}>
                    {step.label}
                  </p>
                  <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">
                    {step.description}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* ── Form ───────────────────────────────────────────────────────── */}
        <form onSubmit={form.handleSubmit(handleSubmit)} className="space-y-6">
          <Card className="overflow-hidden">
            <CardContent className="p-6">
              {/* Step 1: Account Info */}
              {currentStep === 1 && (
                <div className="space-y-4" data-step="1">
                  <div className="mb-6">
                    <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">Account Information</h2>
                    <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                      Create your login credentials
                    </p>
                  </div>

                  <Input
                    label="Full Name"
                    placeholder="John Smith"
                    {...form.register("fullName")}
                    error={form.formState.errors.fullName?.message}
                    leftIcon={<UserCheck className="w-5 h-5" />}
                  />

                  <Input
                    label="Email Address"
                    type="email"
                    placeholder="analyst@company.com"
                    {...form.register("email")}
                    error={form.formState.errors.email?.message}
                    leftIcon={<Mail className="w-5 h-5" />}
                  />

                  <div className="space-y-1.5">
                    <label className="text-sm font-medium text-slate-700 dark:text-slate-300">Password</label>
                    <div className="relative">
                      <Input
                        type={showPassword ? "text" : "password"}
                        placeholder="••••••••••••"
                        {...form.register("password")}
                        error={form.formState.errors.password?.message}
                        leftIcon={<Lock className="w-5 h-5" />}
                      />
                      <button
                        type="button"
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
                        onClick={() => setShowPassword(!showPassword)}
                      >
                        {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                      </button>
                    </div>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      Min 12 chars, uppercase, lowercase, number, special character
                    </p>
                  </div>

                  <Input
                    label="Confirm Password"
                    type={showPassword ? "text" : "password"}
                    placeholder="••••••••••••"
                    {...form.register("confirmPassword")}
                    error={form.formState.errors.confirmPassword?.message}
                    leftIcon={<Lock className="w-5 h-5" />}
                  />
                </div>
              )}

              {/* Step 2: Professional Info */}
              {currentStep === 2 && (
                <div className="space-y-4" data-step="2">
                  <div className="mb-6">
                    <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">Professional Profile</h2>
                    <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                      Help clients understand your expertise
                    </p>
                  </div>

                  <Input
                    label="Professional Title"
                    placeholder="Senior Security Analyst"
                    {...form.register("title")}
                    error={form.formState.errors.title?.message}
                    leftIcon={<UserCheck className="w-5 h-5" />}
                  />

                  <Input
                    label="Company (Optional)"
                    placeholder="CyberSec Consulting LLC"
                    {...form.register("company")}
                    leftIcon={<FileText className="w-5 h-5" />}
                  />

                  <div className="grid grid-cols-2 gap-4">
                    <Input
                      label="Years of Experience"
                      type="number"
                      min="0"
                      max="50"
                      {...form.register("yearsExperience", { valueAsNumber: true })}
                      error={form.formState.errors.yearsExperience?.message}
                    />
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-700 dark:text-slate-300">
                      Specializations <span className="text-red-500">*</span>
                    </label>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      Select all that apply (minimum 1)
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {SPECIALIZATIONS.map((spec, _index) => (
                        <button
                          key={spec}
                          type="button"
                          onClick={() => handleSpecializationChange(spec)}
                          className={cn(
                            "px-3 py-1.5 rounded-full text-sm transition-all border",
                            watchSpecializations?.includes(spec)
                              ? "bg-brand-500 border-brand-500 text-white"
                              : "bg-white dark:bg-slate-800 border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:border-brand-500"
                          )}
                        >
                          {spec}
                        </button>
                      ))}
                    </div>
                    {form.formState.errors.specializations && (
                      <p className="text-sm text-red-500">{form.formState.errors.specializations.message}</p>
                    )}
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-sm font-medium text-slate-700 dark:text-slate-300">Certifications (Optional)</label>
                    <Input
                      placeholder="CISSP, CEH, OSCP, GCIH..."
                      {...form.register("certifications")}
                    />
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      Comma-separated list of relevant certifications
                    </p>
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-sm font-medium text-slate-700 dark:text-slate-300">Professional Bio (Optional)</label>
                    <textarea
                      className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-brand-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900"
                      rows={3}
                      placeholder="Brief description of your experience and approach..."
                      {...form.register("bio")}
                    />
                    <p className="text-xs text-slate-500 dark:text-slate-400 text-right">
                      {form.watch("bio")?.length || 0}/500 characters
                    </p>
                  </div>
                </div>
              )}

              {/* Step 3: Verification */}
              {currentStep === 3 && (
                <div className="space-y-4" data-step="3">
                  <div className="mb-6">
                    <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">Identity Verification</h2>
                    <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                      Required to offer services on the marketplace
                    </p>
                  </div>

                  <Card className="bg-slate-50 dark:bg-slate-900/50">
                    <CardContent className="p-4">
                      <div className="flex items-start gap-3">
                        <div className="w-10 h-10 rounded-lg bg-brand-500/10 flex items-center justify-center flex-shrink-0">
                          <Shield className="w-5 h-5 text-brand-500" />
                        </div>
                        <div>
                          <h3 className="font-medium text-slate-900 dark:text-slate-100">Why verification?</h3>
                          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                            All analysts must complete identity verification before offering services.
                            This protects clients and maintains platform trust.
                          </p>
                          <ul className="mt-3 space-y-1 text-sm text-slate-500 dark:text-slate-400">
                            <li className="flex items-center gap-2">• Government-issued ID (passport, driver's license)</li>
                            <li className="flex items-center gap-2">• Professional license or certification</li>
                            <li className="flex items-center gap-2">• Company verification letter (if applicable)</li>
                          </ul>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <div className="space-y-1.5">
                    <label className="text-sm font-medium text-slate-700 dark:text-slate-300">Upload Verification Document</label>
                    <div className="border-2 border-dashed border-slate-300 dark:border-slate-600 rounded-lg p-6 text-center hover:border-brand-500 transition-colors">
                      <input
                        type="file"
                        accept=".pdf,.jpg,.jpeg,.png"
                        onChange={handleFileChange}
                        className="hidden"
                        id="verification-file"
                        disabled={isSubmitting}
                      />
                      <label htmlFor="verification-file" className="cursor-pointer">
                        <FileText className="w-12 h-12 mx-auto text-slate-400 mb-3" />
                        <p className="text-slate-600 dark:text-slate-400">
                          {verificationFile
                            ? `Selected: ${verificationFile.name} (${(verificationFile.size / 1024 / 1024).toFixed(2)} MB)`
                            : "Click to upload or drag and drop (PDF, JPG, PNG • Max 10MB)"
                          }
                        </p>
                      </label>
                    </div>
                    {form.formState.errors.verificationDoc && (
                      <p className="text-sm text-red-500">{typeof form.formState.errors.verificationDoc.message === "string" ? form.formState.errors.verificationDoc.message : "Invalid file"}</p>
                    )}
                  </div>

                  <div className="space-y-1.5">
                    <label className="flex items-start gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        {...form.register("agreeToTerms")}
                        className="mt-1 rounded border-slate-500 dark:border-slate-400 focus:ring-brand-500"
                      />
                      <span className="text-sm text-slate-600 dark:text-slate-400">
                        I agree to the{" "}
                        <a href="/terms" className="underline text-brand-500 hover:text-brand-600">Terms of Service</a>{" "}
                        and{" "}
                        <a href="/privacy" className="underline text-brand-500 hover:text-brand-600">Privacy Policy</a>.
                        I understand my information will be verified before I can offer services.
                      </span>
                    </label>
                    {form.formState.errors.agreeToTerms && (
                      <p className="text-sm text-red-500 ml-6">{form.formState.errors.agreeToTerms.message}</p>
                    )}
                  </div>

                  <div className="p-4 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800">
                    <div className="flex items-start gap-3">
                      <AlertCircle className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" />
                      <div>
                        <h4 className="font-medium text-amber-800 dark:text-amber-200">Verification Timeline</h4>
                        <p className="text-sm text-amber-700 dark:text-amber-300 mt-1">
                          Verification typically takes 24-48 hours. You'll receive an email notification once approved.
                          You cannot create service offerings until verification is complete.
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Navigation Buttons */}
              <div className="flex justify-between pt-6 border-t border-slate-200 dark:border-slate-700 mt-8">
                <Button
                  type="button"
                  variant="ghost"
                  onClick={prevStep}
                  disabled={currentStep === 1}
                >
                  Back
                </Button>
                <div className="flex gap-3">
                  {currentStep < 3 ? (
                    <Button type="button" onClick={nextStep} rightIcon={<ChevronRight className="w-4 h-4" />}>
                      Continue
                    </Button>
                  ) : (
                    <Button type="submit" isLoading={isSubmitting} rightIcon={<Loader2 className="w-4 h-4 animate-spin" />}>
                      {isSubmitting ? "Submitting..." : "Submit Registration"}
                    </Button>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        </form>

        {/* ── Footer Info ────────────────────────────────────────────────── */}
        <div className="mt-6 text-center">
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Already have an account?{" "}
            <a href="/login" className="text-brand-500 hover:text-brand-600 underline">Sign in</a>
          </p>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-2">
            By registering, you agree to our{" "}
            <a href="/terms" className="underline hover:text-brand-500">Terms of Service</a>{" "}
            and{" "}
            <a href="/privacy" className="underline hover:text-brand-500">Privacy Policy</a>.
          </p>
        </div>
      </div>
    </div>
  );
}