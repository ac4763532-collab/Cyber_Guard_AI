/**
 * CyberGuard AI — Organization Creation (Page 37)
 * ============================================================================
 *
 * Page for creating a new organization/company workspace.
 * Admin creates org, then can invite analysts and manage departments.
 *
 * Flow from Page 2: UserSelection → /organization/create
 *
 * Design: dark navy (#071321) background with cyan/blue accents, Inter font,
 * multi-step form with validation for organization details.
 */

import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Building, UserCheck, Mail, Lock, Eye, EyeOff, ChevronRight, CheckCircle, AlertCircle, Loader2, Shield, Globe, CreditCard } from "lucide-react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { toast } from "sonner";

import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardContent } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { cn } from "@/lib/utils";

const organizationSchema = z.object({
  // Step 1: Organization Info
  name: z.string().min(2, "Organization name is required").max(100),
  slug: z.string().min(2, "Slug is required").max(50)
    .regex(/^[a-z0-9-]+$/, "Only lowercase letters, numbers, and hyphens allowed")
    .refine(val => !val.startsWith("-") && !val.endsWith("-"), "Cannot start or end with hyphen"),
  industry: z.string().min(2, "Industry is required"),
  size: z.enum(["1-10", "11-50", "51-200", "201-500", "501-1000", "1000+"]),
  website: z.string().url("Valid URL required").optional().or(z.literal("")),
  description: z.string().max(500, "Description must be 500 characters or less").optional(),
  // Step 2: Admin Account
  adminEmail: z.string().email("Invalid email address"),
  adminPassword: z.string().min(12, "Password must be at least 12 characters")
    .regex(/[A-Z]/, "Must contain at least one uppercase letter")
    .regex(/[a-z]/, "Must contain at least one lowercase letter")
    .regex(/[0-9]/, "Must contain at least one number")
    .regex(/[^A-Za-z0-9]/, "Must contain at least one special character"),
  adminConfirmPassword: z.string(),
  adminFullName: z.string().min(2, "Full name is required"),
  // Step 3: Plan & Terms
  plan: z.enum(["starter", "professional", "enterprise"]),
  agreeToTerms: z.boolean().refine(val => val === true, "You must agree to the terms"),
}).refine(data => data.adminPassword === data.adminConfirmPassword, {
  message: "Passwords do not match",
  path: ["adminConfirmPassword"],
});

type OrganizationFormValues = z.infer<typeof organizationSchema>;

const INDUSTRIES = [
  "Technology & Software",
  "Financial Services",
  "Healthcare & Life Sciences",
  "Manufacturing & Industrial",
  "Retail & E-commerce",
  "Government & Public Sector",
  "Education",
  "Energy & Utilities",
  "Telecommunications",
  "Media & Entertainment",
  "Transportation & Logistics",
  "Professional Services",
  "Other",
];

const PLANS = [
  {
    id: "starter",
    name: "Starter",
    price: "$49",
    period: "/month",
    description: "Perfect for small teams getting started",
    features: [
      "Up to 10 devices",
      "5 analysts",
      "Basic alerting",
      "Email integration",
      "Community support",
    ],
    popular: false,
  },
  {
    id: "professional",
    name: "Professional",
    price: "$199",
    period: "/month",
    description: "For growing security teams",
    features: [
      "Up to 100 devices",
      "25 analysts",
      "Advanced correlation",
      "All integrations",
      "Priority support",
      "Custom dashboards",
    ],
    popular: true,
  },
  {
    id: "enterprise",
    name: "Enterprise",
    price: "Custom",
    period: "",
    description: "For large organizations with complex needs",
    features: [
      "Unlimited devices",
      "Unlimited analysts",
      "Full platform access",
      "Dedicated support",
      "SLA guarantees",
      "On-premise option",
      "Custom integrations",
    ],
    popular: false,
  },
];

const STEPS = [
  { id: 1, label: "Organization", description: "Company details & settings" },
  { id: 2, label: "Admin Account", description: "Your administrator credentials" },
  { id: 3, label: "Plan", description: "Choose your subscription plan" },
];

export default function OrganizationCreate() {
  const navigate = useNavigate();
  const [currentStep, setCurrentStep] = useState(1);
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [slugAvailable, setSlugAvailable] = useState<"checking" | "available" | "taken" | null>(null);
  const [slugCheckTimeout, setSlugCheckTimeout] = useState<NodeJS.Timeout | null>(null);

  const form = useForm<OrganizationFormValues>({
    resolver: zodResolver(organizationSchema),
    defaultValues: {
      name: "",
      slug: "",
      industry: "",
      size: "1-10",
      website: "",
      description: "",
      adminEmail: "",
      adminPassword: "",
      adminConfirmPassword: "",
      adminFullName: "",
      plan: "professional",
      agreeToTerms: false,
    },
    mode: "onBlur",
  });

  const watchName = form.watch("name");
  const watchSlug = form.watch("slug");

  // Auto-generate slug from name
  useEffect(() => {
    if (watchName && !form.formState.dirtyFields.slug) {
      const generatedSlug = watchName
        .toLowerCase()
        .replace(/[^a-z0-9\s-]/g, "")
        .replace(/\s+/g, "-")
        .replace(/-+/g, "-")
        .replace(/^-|-$/g, "")
        .slice(0, 50);
      form.setValue("slug", generatedSlug, { shouldValidate: true });
    }
  }, [watchName, form]);

  // Check slug availability (debounced)
  useEffect(() => {
    if (slugCheckTimeout) clearTimeout(slugCheckTimeout);

    if (watchSlug && watchSlug.length >= 2) {
      setSlugAvailable("checking");
      setSlugCheckTimeout(setTimeout(() => {
        // Simulate API check
        const takenSlugs = ["cyberguard", "security", "admin", "api", "app", "demo", "test"];
        setSlugAvailable(takenSlugs.includes(watchSlug) ? "taken" : "available");
      }, 300));
    } else {
      setSlugAvailable(null);
    }

    return () => {
      if (slugCheckTimeout) clearTimeout(slugCheckTimeout);
    };
  }, [watchSlug]);

  const nextStep = () => {
    const stepFields: Record<number, (keyof OrganizationFormValues)[]> = {
      1: ["name", "slug", "industry", "size"],
      2: ["adminEmail", "adminPassword", "adminConfirmPassword", "adminFullName"],
      3: ["plan", "agreeToTerms"],
    };

    const fieldsToValidate = stepFields[currentStep] || [];
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

  const handleSubmit = async (_values: OrganizationFormValues) => {
    setIsSubmitting(true);

    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 2500));

      toast.success("Organization created successfully! Redirecting to dashboard...");
      navigate("/dashboard");
    } catch (error) {
      toast.error("Organization creation failed. Please try again.");
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
            <Building className="w-8 h-8 text-brand-500" />
          </div>
          <h1 className="text-3xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Create Your Organization
          </h1>
          <p className="mt-2 text-slate-500 dark:text-slate-400">
            Set up your company workspace and invite your security team
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
              {/* Step 1: Organization Info */}
              {currentStep === 1 && (
                <div className="space-y-4" data-step="1">
                  <div className="mb-6">
                    <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">Organization Details</h2>
                    <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                      Basic information about your company
                    </p>
                  </div>

                  <Input
                    label="Organization Name"
                    placeholder="Acme Corporation"
                    {...form.register("name")}
                    error={form.formState.errors.name?.message}
                    leftIcon={<Building className="w-5 h-5" />}
                  />

                  <div className="relative">
                    <Input
                      label="URL Slug"
                      placeholder="acme-corp"
                      {...form.register("slug")}
                      error={form.formState.errors.slug?.message}
                      leftIcon={<Globe className="w-5 h-5" />}
                    />
                    <div className="absolute right-3 top-[38px] flex items-center gap-1">
                      {slugAvailable === "checking" && <Loader2 className="w-4 h-4 animate-spin text-slate-400" />}
                      {slugAvailable === "available" && <CheckCircle className="w-4 h-4 text-green-500" />}
                      {slugAvailable === "taken" && <AlertCircle className="w-4 h-4 text-red-500" />}
                    </div>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                      {slugAvailable === "available" && "Slug is available"}
                      {slugAvailable === "taken" && "This slug is already taken"}
                      {slugAvailable === "checking" && "Checking availability..."}
                      {!slugAvailable && "Will be used in your organization URL (e.g., app.cyberguard.ai/your-slug)"}
                    </p>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-1.5">
                      <label className="text-sm font-medium text-slate-700 dark:text-slate-300">Industry</label>
                      <select
                        {...form.register("industry")}
                        className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-brand-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900"
                      >
                        <option value="">Select industry</option>
                        {INDUSTRIES.map(industry => (
                          <option key={industry} value={industry}>{industry}</option>
                        ))}
                      </select>
                      {form.formState.errors.industry && (
                        <p className="text-sm text-red-500">{form.formState.errors.industry.message}</p>
                      )}
                    </div>

                    <div className="space-y-1.5">
                      <label className="text-sm font-medium text-slate-700 dark:text-slate-300">Company Size</label>
                      <select
                        {...form.register("size")}
                        className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-brand-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900"
                      >
                        <option value="1-10">1-10 employees</option>
                        <option value="11-50">11-50 employees</option>
                        <option value="51-200">51-200 employees</option>
                        <option value="201-500">201-500 employees</option>
                        <option value="501-1000">501-1000 employees</option>
                        <option value="1000+">1000+ employees</option>
                      </select>
                    </div>
                  </div>

                  <Input
                    label="Website (Optional)"
                    type="url"
                    placeholder="https://acme.com"
                    {...form.register("website")}
                    error={form.formState.errors.website?.message}
                    leftIcon={<Globe className="w-5 h-5" />}
                  />

                  <div className="space-y-1.5">
                    <label className="text-sm font-medium text-slate-700 dark:text-slate-300">Description (Optional)</label>
                    <textarea
                      className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-brand-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900"
                      rows={3}
                      placeholder="Brief description of your organization..."
                      {...form.register("description")}
                    />
                    <p className="text-xs text-slate-500 dark:text-slate-400 text-right">
                      {form.watch("description")?.length || 0}/500 characters
                    </p>
                  </div>
                </div>
              )}

              {/* Step 2: Admin Account */}
              {currentStep === 2 && (
                <div className="space-y-4" data-step="2">
                  <div className="mb-6">
                    <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">Administrator Account</h2>
                    <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                      Create the primary admin account for your organization
                    </p>
                  </div>

                  <Input
                    label="Full Name"
                    placeholder="Jane Administrator"
                    {...form.register("adminFullName")}
                    error={form.formState.errors.adminFullName?.message}
                    leftIcon={<UserCheck className="w-5 h-5" />}
                  />

                  <Input
                    label="Admin Email"
                    type="email"
                    placeholder="admin@acme.com"
                    {...form.register("adminEmail")}
                    error={form.formState.errors.adminEmail?.message}
                    leftIcon={<Mail className="w-5 h-5" />}
                  />

                  <div className="space-y-1.5">
                    <label className="text-sm font-medium text-slate-700 dark:text-slate-300">Password</label>
                    <div className="relative">
                      <Input
                        type={showPassword ? "text" : "password"}
                        placeholder="••••••••••••"
                        {...form.register("adminPassword")}
                        error={form.formState.errors.adminPassword?.message}
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
                    {...form.register("adminConfirmPassword")}
                    error={form.formState.errors.adminConfirmPassword?.message}
                    leftIcon={<Lock className="w-5 h-5" />}
                  />

                  <Card className="bg-slate-50 dark:bg-slate-900/50 border-slate-200 dark:border-slate-700">
                    <CardContent className="p-4">
                      <div className="flex items-start gap-3">
                        <div className="w-10 h-10 rounded-lg bg-brand-500/10 flex items-center justify-center flex-shrink-0">
                          <Shield className="w-5 h-5 text-brand-500" />
                        </div>
                        <div>
                          <h3 className="font-medium text-slate-900 dark:text-slate-100">Admin Permissions</h3>
                          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                            This account will have full administrative access including:
                          </p>
                          <ul className="mt-2 space-y-1 text-sm text-slate-500 dark:text-slate-400">
                            <li className="flex items-center gap-2">• Manage organization settings & billing</li>
                            <li className="flex items-center gap-2">• Invite/remove analysts & team members</li>
                            <li className="flex items-center gap-2">• Create departments & manage access</li>
                            <li className="flex items-center gap-2">• View all alerts, incidents & audit logs</li>
                          </ul>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              )}

              {/* Step 3: Plan Selection */}
              {currentStep === 3 && (
                <div className="space-y-4" data-step="3">
                  <div className="mb-6">
                    <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">Choose Your Plan</h2>
                    <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                      Select the plan that fits your organization's needs
                    </p>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {PLANS.map((plan) => (
                      <div
                        key={plan.id}
                        className={cn(
                          "relative rounded-xl border-2 p-6 transition-all",
                          form.watch("plan") === plan.id
                            ? "border-brand-500 bg-brand-500/5 dark:bg-brand-900/10"
                            : "border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600"
                        )}
                      >
                        {plan.popular && (
                          <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                            <Badge variant="custom" customClassName="bg-brand-500 text-white" className="text-xs">Most Popular</Badge>
                          </div>
                        )}
                        <button
                          type="button"
                          onClick={() => form.setValue("plan", plan.id as "starter" | "professional" | "enterprise")}
                          className="w-full text-left"
                        >
                          <div className="flex items-baseline gap-1 mb-2">
                            <span className="text-3xl font-bold text-slate-900 dark:text-slate-100">{plan.price}</span>
                            <span className="text-slate-500 dark:text-slate-400">{plan.period}</span>
                          </div>
                          <h3 className="font-semibold text-slate-900 dark:text-slate-100 mb-1">{plan.name}</h3>
                          <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">{plan.description}</p>
                          <ul className="space-y-2">
                            {plan.features.map((feature, idx) => (
                              <li key={idx} className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-400">
                                <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0" />
                                {feature}
                              </li>
                            ))}
                          </ul>
                        </button>
                      </div>
                    ))}
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
                        I understand billing will start after the 14-day free trial.
                      </span>
                    </label>
                    {form.formState.errors.agreeToTerms && (
                      <p className="text-sm text-red-500 ml-6">{form.formState.errors.agreeToTerms.message}</p>
                    )}
                  </div>

                  <Card className="bg-slate-50 dark:bg-slate-900/50 border-slate-200 dark:border-slate-700">
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <CreditCard className="w-5 h-5 text-brand-500" />
                        <div>
                          <h4 className="font-medium text-slate-900 dark:text-slate-100">14-Day Free Trial</h4>
                          <p className="text-sm text-slate-500 dark:text-slate-400">
                            No credit card required to start. Cancel anytime during trial.
                          </p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
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
                      {isSubmitting ? "Creating Organization..." : "Create Organization"}
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
            Already have an organization?{" "}
            <a href="/login" className="text-brand-500 hover:text-brand-600 underline">Sign in</a>
          </p>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-2">
            By creating an organization, you agree to our{" "}
            <a href="/terms" className="underline hover:text-brand-500">Terms of Service</a>{" "}
            and{" "}
            <a href="/privacy" className="underline hover:text-brand-500">Privacy Policy</a>.
          </p>
        </div>
      </div>
    </div>
  );
}