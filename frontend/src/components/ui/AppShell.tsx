/**
 * CyberGuard AI — Role-Based App Shell Layout
 * ============================================================================
 * 
 * The primary structural frame enforcing strict role-based navigation:
 *   - Individual: sees only personal security pages (Devices, Email, Logs, Network, Alerts, Rooms).
 *   - Security Analyst: sees only analyst operations pages (Cases, Evidence, AI Investigation, Reports).
 *   - Organization: sees only company administration pages (Rooms, Workspace, Employees, Analysts).
 * 
 * Cross-role navigation is completely isolated.
 */

import React, { useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  Shield,
  LayoutDashboard,
  Server,
  Bell,
  FileText,
  Settings,
  Menu,
  LogOut,
  Moon,
  Sun,
  ShieldCheck,
  Mail,
  Terminal,
  Wifi,
  Bot,
  Users,
  MessageSquare,
  DoorOpen,
  Briefcase,
  FolderOpen,
  Database,
  Microscope,
  CreditCard,
  UserCheck,
  Building,
  UserPlus,
  Copy,
  Check,
  Layers,
  Laptop,
  ShieldAlert,
  Building2,
} from "lucide-react";

import { useAuth } from "@/auth/AuthProvider";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/Button";
import { ThemeToggle } from "@/components/ui/ThemeToggle";
import { Breadcrumbs } from "@/components/common/Breadcrumbs";
import { toast } from "sonner";
import {
  Modal,
  ModalContent,
  ModalHeader,
  ModalTitle,
  ModalDescription,
} from "@/components/ui/Modal";

interface NavItem {
  label: string;
  href: string;
  icon: React.ReactNode;
  badge?: string;
}

// ── 1. Individual Workspace Navigation (Pages 5, 6, 8, 10, 11, 13, 16, 17, 18, 19, 20, 57)
const individualNav: NavItem[] = [
  { label: "Personal Dashboard", href: "/personal/dashboard", icon: <LayoutDashboard size={18} /> },
  { label: "My Devices", href: "/personal/devices", icon: <Server size={18} /> },
  { label: "Gmail & Email Security", href: "/personal/email", icon: <Mail size={18} /> },
  { label: "Log Monitoring", href: "/personal/logs", icon: <Terminal size={18} /> },
  { label: "Network Security", href: "/personal/network", icon: <Wifi size={18} /> },
  { label: "Security Alert Center", href: "/personal/alerts", icon: <Bell size={18} /> },
  { label: "AI Security Assistant", href: "/personal/ai-assistant", icon: <Bot size={18} /> },
  { label: "Security Analysts", href: "/personal/analysts", icon: <Users size={18} /> },
  { label: "Messages", href: "/personal/messages", icon: <MessageSquare size={18} /> },
  { label: "Combined Reports", href: "/personal/reports", icon: <FileText size={18} /> },
  { label: "My Rooms & Invitations", href: "/personal/rooms", icon: <DoorOpen size={18} />, badge: "Join" },
  { label: "Profile & Settings", href: "/personal/settings", icon: <Settings size={18} /> },
];

// ── 2. Analyst Workspace Navigation (Pages 25, 26, 27, 29, 30, 31, 32, 33, 34, 35, 36)
const analystNav: NavItem[] = [
  { label: "Analyst Dashboard", href: "/analyst/dashboard", icon: <LayoutDashboard size={18} /> },
  { label: "My Cases", href: "/analyst/cases", icon: <Briefcase size={18} /> },
  { label: "Available Cases", href: "/analyst/available-cases", icon: <FolderOpen size={18} /> },
  { label: "Evidence Library", href: "/analyst/evidence", icon: <Database size={18} /> },
  { label: "Investigation Workbench", href: "/analyst/ai-investigation", icon: <Microscope size={18} /> },
  { label: "Case & Direct Messages", href: "/analyst/messages", icon: <MessageSquare size={18} /> },
  { label: "Investigation Reports", href: "/analyst/reports", icon: <FileText size={18} /> },
  { label: "My Services", href: "/analyst/services", icon: <Shield size={18} /> },
  { label: "Profile & Verification", href: "/analyst/profile", icon: <UserCheck size={18} /> },
  { label: "Earnings & Payments", href: "/analyst/earnings", icon: <CreditCard size={18} /> },
  { label: "Analyst Settings", href: "/analyst/settings", icon: <Settings size={18} /> },
];

// ── 3. Organization Workspace Navigation (Pages 39, 40, 42, 51, 55)
const organizationNav: NavItem[] = [
  { label: "Organization Dashboard", href: "/organization/dashboard", icon: <LayoutDashboard size={18} /> },
  { label: "Rooms & Workspaces", href: "/organization/rooms", icon: <Building size={18} /> },
  { label: "Employees & Members", href: "/organization/employees", icon: <Users size={18} /> },
  { label: "Hire Security Analysts", href: "/organization/analysts", icon: <UserPlus size={18} /> },
  { label: "Organization Settings", href: "/organization/settings", icon: <Settings size={18} /> },
];

export function AppShell() {
  const { user, logout, switchRole } = useAuth();
  const navigate = useNavigate();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [copiedId, setCopiedId] = useState(false);
  const [showRoleModal, setShowRoleModal] = useState(false);
  const [isSwitchingRole, setIsSwitchingRole] = useState(false);

  const handleSwitchWorkspace = async (targetRole: string, targetPath: string) => {
    setIsSwitchingRole(true);
    try {
      await switchRole(targetRole);
      setShowRoleModal(false);
      navigate(targetPath, { replace: true });
      toast.success(`Switched to ${targetRole} workspace!`);
    } catch (err: any) {
      toast.error(err.message || "Failed to switch workspace");
    } finally {
      setIsSwitchingRole(false);
    }
  };

  const role = (user?.role || "individual").toLowerCase();
  
  // Choose navigation according to role
  let navItems: NavItem[] = individualNav;
  let roleTitle = "Individual Protection";
  let roleBadgeClass = "bg-cyan-500/10 text-cyan-400 border-cyan-500/30";

  if (role === "analyst") {
    navItems = analystNav;
    roleTitle = "Security Analyst Operations";
    roleBadgeClass = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
  } else if (role === "organizer" || role === "org_admin" || role === "organization") {
    navItems = organizationNav;
    roleTitle = "Organization Workspace";
    roleBadgeClass = "bg-blue-500/10 text-blue-400 border-blue-500/30";
  }

  const copyPublicId = () => {
    if (user?.public_user_id) {
      navigator.clipboard.writeText(user.public_user_id);
      setCopiedId(true);
      toast.success("Security ID copied to clipboard!");
      setTimeout(() => setCopiedId(false), 2000);
    }
  };

  return (
    <div className="flex h-screen w-full bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 overflow-hidden font-sans transition-colors">
      
      {/* ── Mobile Sidebar Overlay ─────────────────────────────────────── */}
      {isMobileMenuOpen && (
        <div
          className="fixed inset-0 z-40 bg-slate-950/80 backdrop-blur-sm lg:hidden"
          onClick={() => setIsMobileMenuOpen(false)}
        />
      )}

      {/* ── Sidebar ────────────────────────────────────────────────────── */}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-50 w-72 flex-col border-r border-slate-200 dark:border-slate-800 bg-white/95 dark:bg-slate-900/95 backdrop-blur-md transition-all duration-200 ease-in-out lg:static lg:flex lg:translate-x-0",
          isMobileMenuOpen ? "flex translate-x-0" : "hidden -translate-x-full lg:flex"
        )}
      >
        {/* Brand Header */}
        <div className="flex h-20 items-center justify-between border-b border-slate-200/80 dark:border-slate-800/80 px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-600 dark:text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.25)]">
              <ShieldCheck className="h-6 w-6" />
            </div>
            <div>
              <span className="text-lg font-black tracking-wider text-slate-900 dark:text-slate-100">
                CYBER<span className="text-cyan-600 dark:text-cyan-400">GUARD</span>
              </span>
              <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500 dark:text-slate-400">
                AI Defense Platform
              </p>
            </div>
          </div>
        </div>

        {/* User Identity & Security ID Badge */}
        <div className="p-4 border-b border-slate-200/60 dark:border-slate-800/60 bg-slate-100/60 dark:bg-slate-950/40">
          <div className="flex items-center justify-between mb-2">
            <span className={cn("text-[11px] font-semibold px-2 py-0.5 rounded-full border uppercase tracking-wider", roleBadgeClass)}>
              {roleTitle}
            </span>
            <button
              onClick={() => setShowRoleModal(true)}
              className="text-[10px] font-bold text-cyan-600 dark:text-cyan-400 hover:text-cyan-500 dark:hover:text-cyan-300 flex items-center gap-1 hover:underline transition"
              title="Switch Workspace Portal"
            >
              <Layers size={11} /> Switch
            </button>
          </div>

          <div className="flex items-center justify-between bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-2.5 shadow-sm">
            <div className="truncate pr-2">
              <p className="text-[11px] text-slate-500 dark:text-slate-400">Security ID</p>
              <p className="font-mono text-xs font-bold text-cyan-600 dark:text-cyan-300 truncate">
                {user?.public_user_id || "Generating..."}
              </p>
            </div>
            <button
              onClick={copyPublicId}
              title="Copy Security ID"
              className="p-1.5 rounded-md text-slate-400 hover:text-cyan-500 dark:hover:text-cyan-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
            >
              {copiedId ? <Check size={15} className="text-emerald-500" /> : <Copy size={15} />}
            </button>
          </div>
        </div>

        {/* Role-Specific Navigation Links */}
        <nav className="flex-1 overflow-y-auto py-3 px-3 space-y-1">
          {navItems.map((item) => (
            <NavLink
              key={item.href}
              to={item.href}
              onClick={() => setIsMobileMenuOpen(false)}
              className={({ isActive }) =>
                cn(
                  "flex items-center justify-between rounded-lg px-3 py-2.5 text-xs font-semibold tracking-wide transition-all duration-150",
                  isActive
                    ? "bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-[0_0_12px_rgba(6,182,212,0.15)]"
                    : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-200"
                )
              }
            >
              <div className="flex items-center gap-3">
                <span className="text-slate-400">{item.icon}</span>
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span className="text-[10px] uppercase font-bold px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  {item.badge}
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        {/* Logout & Footer */}
        <div className="border-t border-slate-800/80 p-4 bg-slate-950/60">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5 truncate">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-cyan-500/20 font-bold text-cyan-400 text-xs border border-cyan-500/30">
                {user?.full_name?.charAt(0).toUpperCase() || user?.email?.charAt(0).toUpperCase() || "U"}
              </div>
              <div className="truncate">
                <p className="text-xs font-bold text-slate-200 truncate">{user?.full_name || "Account"}</p>
                <p className="text-[11px] text-slate-500 truncate">{user?.email}</p>
              </div>
            </div>
            <button
              onClick={logout}
              title="Sign Out"
              className="p-2 text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition"
            >
              <LogOut size={16} />
            </button>
          </div>
        </div>
      </aside>

      {/* ── Main Area ──────────────────────────────────────────────────── */}
      <div className="flex flex-1 flex-col overflow-hidden">
        
        {/* Topbar */}
        <header className="flex h-16 shrink-0 items-center justify-between border-b border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-slate-900/80 px-4 backdrop-blur-md lg:px-8 transition-colors">
          <div className="flex items-center gap-3">
            <button
              className="rounded-md p-2 text-slate-500 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800 lg:hidden"
              onClick={() => setIsMobileMenuOpen(true)}
            >
              <Menu size={20} />
            </button>
            <div className="hidden sm:flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
              <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></span>
              <span className="font-medium">Defense Engine Active</span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Quick Action: Direct Join Room (visible for Individuals) */}
            {role === "individual" && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => navigate("/personal/rooms")}
                className="hidden sm:flex items-center gap-2 text-xs border-cyan-500/30 text-cyan-600 dark:text-cyan-400 hover:bg-cyan-500/10"
              >
                <DoorOpen size={14} />
                Join Room
              </Button>
            )}

            {/* Quick Portal Switcher Button */}
            <button
              onClick={() => setShowRoleModal(true)}
              className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold bg-slate-100 hover:bg-slate-200 dark:bg-slate-800/80 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 hover:text-cyan-600 dark:hover:text-cyan-400 border border-slate-200 dark:border-slate-700 transition shadow-sm"
              title="Switch Workspace Portal"
            >
              <Layers size={13} className="text-cyan-500 dark:text-cyan-400" />
              <span>Portal: <strong className="capitalize text-slate-900 dark:text-slate-100">{role === "organizer" || role === "org_admin" ? "Organization" : role}</strong></span>
            </button>

            {/* Dark / Light Mode Switch */}
            <ThemeToggle />

            {/* User Chip */}
            <div className="flex items-center gap-2 border-l border-slate-200 dark:border-slate-800 pl-3">
              <span className="text-xs font-semibold text-slate-700 dark:text-slate-300 hidden md:inline">
                {user?.full_name || user?.email}
              </span>
            </div>
          </div>
        </header>

        {/* Content Area */}
        <main className="flex-1 overflow-y-auto bg-slate-50 dark:bg-slate-950 p-4 sm:p-6 lg:p-8 transition-colors">
          <div className="mx-auto max-w-7xl">
            <Breadcrumbs />
            <Outlet />
          </div>
        </main>
      </div>

      {/* ── Workspace Role Switcher Modal ────────────────────────────── */}
      <Modal open={showRoleModal} onOpenChange={setShowRoleModal}>
        <ModalContent className="max-w-md">
          <ModalHeader>
            <div className="flex items-center gap-2 text-cyan-400 mb-1">
              <Layers size={20} />
              <ModalTitle>Switch Workspace Portal</ModalTitle>
            </div>
            <ModalDescription>
              Select the workspace you want to enter. Your authorized permissions will update seamlessly.
            </ModalDescription>
          </ModalHeader>

          <div className="space-y-3 py-2">
            {/* Individual */}
            <button
              onClick={() => handleSwitchWorkspace("individual", "/personal/dashboard")}
              disabled={isSwitchingRole}
              className={cn(
                "w-full text-left p-3.5 rounded-xl border transition flex items-start gap-3.5 cursor-pointer",
                role === "individual"
                  ? "border-cyan-500 bg-cyan-500/10 text-cyan-300"
                  : "border-slate-800 bg-slate-900/60 hover:border-slate-700 text-slate-300"
              )}
            >
              <div className="p-2 rounded-lg bg-slate-800 text-cyan-400 shrink-0">
                <Laptop size={18} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-100">Individual Protection</span>
                  {role === "individual" && <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">Active</span>}
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Personal endpoint defense, Gmail security, system logs, and AI Assistant.
                </p>
              </div>
            </button>

            {/* Analyst */}
            <button
              onClick={() => handleSwitchWorkspace("analyst", "/analyst/dashboard")}
              disabled={isSwitchingRole}
              className={cn(
                "w-full text-left p-3.5 rounded-xl border transition flex items-start gap-3.5 cursor-pointer",
                role === "analyst"
                  ? "border-emerald-500 bg-emerald-500/10 text-emerald-300"
                  : "border-slate-800 bg-slate-900/60 hover:border-slate-700 text-slate-300"
              )}
            >
              <div className="p-2 rounded-lg bg-slate-800 text-emerald-400 shrink-0">
                <ShieldAlert size={18} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-100">Security Analyst (SOC)</span>
                  {role === "analyst" && <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">Active</span>}
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  SOC case workbench, threat hunting, evidence vault, and investigation reports.
                </p>
              </div>
            </button>

            {/* Organization */}
            <button
              onClick={() => handleSwitchWorkspace("organizer", "/organization/dashboard")}
              disabled={isSwitchingRole}
              className={cn(
                "w-full text-left p-3.5 rounded-xl border transition flex items-start gap-3.5 cursor-pointer",
                role === "organizer" || role === "org_admin"
                  ? "border-blue-500 bg-blue-500/10 text-blue-300"
                  : "border-slate-800 bg-slate-900/60 hover:border-slate-700 text-slate-300"
              )}
            >
              <div className="p-2 rounded-lg bg-slate-800 text-blue-400 shrink-0">
                <Building2 size={18} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-100">Organization Console</span>
                  {(role === "organizer" || role === "org_admin") && <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-blue-500/20 text-blue-300 border border-blue-500/30">Active</span>}
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Enterprise telemetry, department rooms, employee monitoring, and analyst hiring.
                </p>
              </div>
            </button>
          </div>
        </ModalContent>
      </Modal>
    </div>
  );
}

export default AppShell;
