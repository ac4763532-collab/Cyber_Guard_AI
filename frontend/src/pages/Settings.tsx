/**
 * CyberGuard AI — Settings Page
 * ============================================================================
 * 
 * User account management.
 * 
 * Sections:
 *   1. Profile: Update name, timezone, and language.
 *   2. Security: Change password.
 *   3. Danger Zone: Sign out of all devices.
 * 
 * Uses React Hook Form + Zod for validation, and updates the AuthContext
 * user data immediately on success so the UI reflects changes without
 * requiring a page refresh.
 */

import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { User, Shield, AlertTriangle } from "lucide-react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import { useAuth } from "@/auth/AuthProvider";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";


// ============================================================================
// SCHEMAS
// ============================================================================

const profileSchema = z.object({
  fullName: z.string().min(1, "Name is required"),
  timezone: z.string().min(1, "Timezone is required"),
  preferredLanguage: z.string().min(2, "Language code is required"),
});

const passwordSchema = z.object({
  oldPassword: z.string().min(1, "Current password is required"),
  newPassword: z.string().min(8, "New password must be at least 8 characters"),
  confirmPassword: z.string().min(1, "Please confirm your new password"),
}).refine((data) => data.newPassword === data.confirmPassword, {
  message: "Passwords do not match",
  path: ["confirmPassword"],
});


// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function Settings() {
  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
          Settings
        </h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          Manage your account preferences and security settings.
        </p>
      </div>

      <ProfileSection />
      <SecuritySection />
      <DangerZone />
    </div>
  );
}


// ============================================================================
// PROFILE SECTION
// ============================================================================

function ProfileSection() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [isSaving, setIsSaving] = useState(false);

  const form = useForm({
    resolver: zodResolver(profileSchema),
    defaultValues: {
      fullName: user?.full_name || "",
      timezone: user?.timezone || "UTC",
      preferredLanguage: user?.preferred_language || "en",
    },
  });

  const mutation = useMutation({
    mutationFn: async (data: any) => {
      const response = await api.patch("/users/me", {
        full_name: data.fullName,
        timezone: data.timezone,
        preferred_language: data.preferredLanguage,
      });
      return response.data;
    },
    onSuccess: (data) => {
      toast.success("Profile updated successfully");
      // Update the global cache so the topbar updates instantly
      queryClient.setQueryData(["me"], data);
      setIsSaving(false);
    },
    onError: (err: any) => {
      toast.error(err.message || "Failed to update profile");
      setIsSaving(false);
    },
  });

  const onSubmit = (data: any) => {
    setIsSaving(true);
    mutation.mutate(data);
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <User size={20} className="text-brand-500" />
          <CardTitle>Profile</CardTitle>
        </div>
        <CardDescription>Update your personal information and locale.</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Input
              label="Full Name"
              {...form.register("fullName")}
              error={form.formState.errors.fullName?.message as string}
            />
            <Input
              label="Email Address"
              value={user?.email}
              disabled
              helperText="Email cannot be changed directly."
            />
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-slate-700 dark:text-slate-300">Timezone</label>
              <select
                className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-brand-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900"
                {...form.register("timezone")}
              >
                <option value="UTC">UTC</option>
                <option value="America/New_York">America/New_York (EST)</option>
                <option value="America/Los_Angeles">America/Los_Angeles (PST)</option>
                <option value="Europe/London">Europe/London (GMT)</option>
                <option value="Asia/Kolkata">Asia/Kolkata (IST)</option>
              </select>
            </div>
            <div className="space-y-1.5">
              <label className="text-sm font-medium text-slate-700 dark:text-slate-300">Language</label>
              <select
                className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-brand-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900"
                {...form.register("preferredLanguage")}
              >
                <option value="en">English</option>
                <option value="es">Español</option>
                <option value="hi">हिन्दी</option>
                <option value="fr">Français</option>
              </select>
            </div>
          </div>
          <div className="flex justify-end pt-2">
            <Button type="submit" isLoading={isSaving}>Save Changes</Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}


// ============================================================================
// SECURITY SECTION
// ============================================================================

function SecuritySection() {
  const [isSaving, setIsSaving] = useState(false);

  const form = useForm({
    resolver: zodResolver(passwordSchema),
    defaultValues: {
      oldPassword: "",
      newPassword: "",
      confirmPassword: "",
    },
  });

  const mutation = useMutation({
    mutationFn: async (data: any) => {
      await api.post("/auth/change-password", {
        old_password: data.oldPassword,
        new_password: data.newPassword,
      });
    },
    onSuccess: () => {
      toast.success("Password changed successfully");
      form.reset();
      setIsSaving(false);
    },
    onError: (err: any) => {
      toast.error(err.message || "Failed to change password");
      setIsSaving(false);
    },
  });

  const onSubmit = (data: any) => {
    setIsSaving(true);
    mutation.mutate(data);
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Shield size={20} className="text-brand-500" />
          <CardTitle>Security</CardTitle>
        </div>
        <CardDescription>Change your password to keep your account secure.</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4 max-w-md">
          <Input
            label="Current Password"
            type="password"
            {...form.register("oldPassword")}
            error={form.formState.errors.oldPassword?.message as string}
          />
          <Input
            label="New Password"
            type="password"
            {...form.register("newPassword")}
            error={form.formState.errors.newPassword?.message as string}
            helperText="Minimum 8 characters."
          />
          <Input
            label="Confirm New Password"
            type="password"
            {...form.register("confirmPassword")}
            error={form.formState.errors.confirmPassword?.message as string}
          />
          <div className="flex justify-end pt-2">
            <Button type="submit" isLoading={isSaving}>Update Password</Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}


// ============================================================================
// DANGER ZONE
// ============================================================================

function DangerZone() {
  const { logout } = useAuth();

  return (
    <Card className="border-red-200 dark:border-red-900">
      <CardHeader>
        <div className="flex items-center gap-2">
          <AlertTriangle size={20} className="text-red-500" />
          <CardTitle className="text-red-600 dark:text-red-400">Danger Zone</CardTitle>
        </div>
        <CardDescription>Actions here affect your entire account.</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex items-center justify-between">
          <div>
            <p className="font-medium text-slate-900 dark:text-slate-100">Sign out of all devices</p>
            <p className="text-sm text-slate-500">This will invalidate your session on this device and log you out.</p>
          </div>
          <Button variant="danger" onClick={logout}>
            Sign Out
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}