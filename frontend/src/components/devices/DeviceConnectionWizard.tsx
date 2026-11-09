/**
 * CyberGuard AI — Non-Technical Device Connection Wizard
 * ============================================================================
 * 5-Screen guided setup allowing non-technical users to connect Windows
 * and Linux computers without terminal commands, PowerShell, or manual configuration.
 *
 * Screens:
 *   1. Choose Device (Windows / Linux + OS specifications & requirements)
 *   2. Download Installer (Signed Windows installer / guided Linux package + SHA256)
 *   3. Automatic Secure Enrollment (Short-lived tokens, DPAPI encryption, tenant isolation)
 *   4. Installation & Connection Progress (Real-time 8-stage backend checkpoint tracker)
 *   5. Connected Device (Verified ONLINE status, permissions, heartbeat, telemetry)
 */

import React, { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  Monitor,
  Server,
  Download,
  ShieldCheck,
  CheckCircle2,
  Clock,
  AlertCircle,
  Copy,
  Check,
  ArrowRight,
  ArrowLeft,
  RefreshCw,
  Lock,
  Activity,
  FileCheck,
  Zap,
  HelpCircle,
  Info,
  ChevronRight,
  ChevronDown,
  ShieldAlert,
} from "lucide-react";
import {
  Modal,
  ModalContent,
  ModalHeader,
  ModalTitle,
  ModalDescription,
  ModalFooter,
} from "@/components/ui/Modal";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Spinner } from "@/components/ui/Spinner";
import { Card, CardContent } from "@/components/ui/Card";
import { api } from "@/lib/api";
import { formatRelativeTime } from "@/lib/utils";
import { toast } from "sonner";

export type OSType = "windows" | "linux";

interface DeviceRegisterResponse {
  id: string;
  source_key: string;
  name: string;
  os_type: string;
  status: string;
  enrollment_token: string;
  expires_at: string;
  installer_download_url: string;
  installer_version: string;
  publisher: string;
  file_size_bytes: number;
  sha256_checksum: string;
  powershell_install_command?: string;
  bash_install_command?: string;
}

interface EnrollmentStatus {
  device_id: string;
  device_name: string;
  source_key: string;
  os_type: string;
  status: "online" | "offline" | "pending" | "at_risk" | "revoked";
  collector_connected: boolean;
  last_heartbeat: string | null;
  last_event_at: string | null;
  collector_version: string;
  collection_permissions: string[];
  events_received: number;
  installer_downloaded: boolean;
  installation_started: boolean;
  collector_installed: boolean;
  device_authenticated: boolean;
  device_enrolled: boolean;
  service_started: boolean;
  first_heartbeat_received: boolean;
  first_telemetry_received: boolean;
  installer_downloaded_at: string | null;
  installation_started_at: string | null;
  collector_installed_at: string | null;
  device_authenticated_at: string | null;
  device_enrolled_at: string | null;
  service_started_at: string | null;
  first_heartbeat_at: string | null;
  first_telemetry_at: string | null;
  error_message: string | null;
  recovery_hint: string | null;
}

interface DeviceConnectionWizardProps {
  isOpen: boolean;
  onClose: () => void;
  preselectedDevice?: { id: string; name: string; os_type: string } | null;
}

export function DeviceConnectionWizard({
  isOpen,
  onClose,
  preselectedDevice,
}: DeviceConnectionWizardProps) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  // Wizard Screen: 1 to 5
  const [screen, setScreen] = useState<number>(1);
  const [os, setOs] = useState<OSType>("windows");
  const [deviceName, setDeviceName] = useState("");
  const [deviceData, setDeviceData] = useState<DeviceRegisterResponse | null>(null);
  const [copiedHash, setCopiedHash] = useState(false);
  const [copiedToken, setCopiedToken] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);
  const [showHelp, setShowHelp] = useState(false);

  const formatFriendlyError = (errStr: string | null | undefined) => {
    if (!errStr) return { title: "", hint: "" };
    const lower = errStr.toLowerCase();
    if (lower.includes("token") || lower.includes("invalid") || lower.includes("expired")) {
      return {
        title: "We couldn't securely connect this computer.",
        hint: "Return to CyberGuard AI and try connecting again.",
      };
    }
    if (lower.includes("heartbeat") || lower.includes("timeout") || lower.includes("unreachable")) {
      return {
        title: "Your computer is not currently communicating with CyberGuard AI.",
        hint: "Check its internet connection.",
      };
    }
    if (lower.includes("permission") || lower.includes("denied") || lower.includes("admin")) {
      return {
        title: "Windows needs permission to install the security monitoring service.",
        hint: "When prompted by Windows, click 'Yes' to allow the installation.",
      };
    }
    return {
      title: errStr,
      hint: "Please ensure your computer is powered on and connected to the internet.",
    };
  };

  // If reopening for an existing device
  useEffect(() => {
    if (preselectedDevice) {
      setDeviceName(preselectedDevice.name);
      setOs(preselectedDevice.os_type === "linux" ? "linux" : "windows");
    }
  }, [preselectedDevice]);

  // ── Mutation: Register Device & Generate One-Time Challenge ─────────
  const registerMutation = useMutation({
    mutationFn: async () => {
      const { data } = await api.post<DeviceRegisterResponse>("/devices", {
        name: deviceName.trim() || `My ${os === "windows" ? "Windows PC" : "Linux Machine"}`,
        os_type: os,
      });
      return data;
    },
    onSuccess: (data) => {
      setDeviceData(data);
      setScreen(2);
      queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
    onError: (err: any) => {
      toast.error(err?.message || "Failed to initiate device enrollment");
    },
  });

  // ── Query: Live Real-time Enrollment Checkpoints (Screen 4) ─────────
  const activeDeviceId = deviceData?.id || preselectedDevice?.id;
  const { data: statusData, refetch: refetchStatus } = useQuery<EnrollmentStatus>({
    queryKey: ["device-enrollment-status", activeDeviceId],
    queryFn: async () => {
      if (!activeDeviceId) throw new Error("No active device ID");
      const { data } = await api.get<EnrollmentStatus>(`/devices/${activeDeviceId}/enrollment-status`);
      return data;
    },
    enabled: isOpen && (screen === 4 || screen === 5) && !!activeDeviceId,
    refetchInterval: screen === 4 ? 1500 : 8000,
  });

  // Auto-advance to Screen 5 once backend confirms online heartbeat & enrollment
  useEffect(() => {
    if (screen === 4 && statusData) {
      if (
        statusData.collector_connected &&
        statusData.device_enrolled &&
        statusData.first_heartbeat_received
      ) {
        setScreen(5);
        toast.success("Device connected and verified online!");
        queryClient.invalidateQueries({ queryKey: ["devices"] });
      }
    }
  }, [statusData, screen, queryClient]);

  // Reset wizard on close
  const handleClose = () => {
    onClose();
    setTimeout(() => {
      setScreen(1);
      setDeviceData(null);
      setDeviceName("");
      setCopiedHash(false);
      setCopiedToken(false);
    }, 250);
  };

  // Helper to trigger genuine installer download
  const handleDownloadInstaller = async () => {
    if (!deviceData && !preselectedDevice) return;
    setIsDownloading(true);
    const id = deviceData?.id || preselectedDevice?.id;
    try {
      const tokenParam = deviceData?.enrollment_token ? `&token=${encodeURIComponent(deviceData.enrollment_token)}` : "";
      const res = await api.get(`/devices/${id}/installer?os=${os}${tokenParam}`, {
        responseType: "blob",
      });

      const blob = new Blob([res.data], {
        type: os === "windows" ? "application/vnd.microsoft.portable-executable" : "text/x-shellscript",
      });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = os === "windows" ? "CyberGuardSetup.exe" : "install_linux.sh";
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

      toast.success(
        os === "windows"
          ? "CyberGuardSetup.exe downloaded! Open it to start protection."
          : "install_linux.sh downloaded!"
      );

      // Auto-copy enrollment token to clipboard so smart installer auto-detects it
      if (deviceData?.enrollment_token) {
        try {
          await navigator.clipboard.writeText(deviceData.enrollment_token);
        } catch { }
      }

      // Auto-download companion config file for zero-click Windows setup
      if (os === "windows" && deviceData?.enrollment_token) {
        try {
          const configJson = JSON.stringify(
            {
              server_url: "http://127.0.0.1:8000",
              device_id: id,
              enrollment_token: deviceData.enrollment_token,
            },
            null,
            2
          );
          const cfgBlob = new Blob([configJson], { type: "application/json" });
          const cfgUrl = window.URL.createObjectURL(cfgBlob);
          const cfgA = document.createElement("a");
          cfgA.href = cfgUrl;
          cfgA.download = "cyberguard-config.json";
          document.body.appendChild(cfgA);
          cfgA.click();
          cfgA.remove();
          window.URL.revokeObjectURL(cfgUrl);
        } catch { }
      }

      // Move to Screen 3 (Security Overview) or Screen 4 (Live Progress)
      setTimeout(() => {
        setScreen(3);
      }, 800);
    } catch (err: any) {
      toast.error(err?.message || "Failed to download installer package.");
    } finally {
      setIsDownloading(false);
    }
  };

  const handleCopyHash = () => {
    if (!deviceData?.sha256_checksum) return;
    navigator.clipboard.writeText(deviceData.sha256_checksum);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
    toast.success("SHA-256 integrity hash copied");
  };

  const handleCopyToken = () => {
    if (!deviceData?.enrollment_token) return;
    navigator.clipboard.writeText(deviceData.enrollment_token);
    setCopiedToken(true);
    setTimeout(() => setCopiedToken(false), 2000);
    toast.success("Enrollment token copied");
  };

  return (
    <Modal open={isOpen} onOpenChange={handleClose}>
      <ModalContent className="max-w-2xl bg-slate-900 border-slate-800 text-slate-100 p-0 overflow-hidden shadow-2xl">
        {/* ── Wizard Header & Step Tracker ────────────────────────────── */}
        <div className="bg-slate-950 border-b border-slate-800 px-6 py-5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                <ShieldCheck size={20} />
              </div>
              <div>
                <ModalTitle className="text-lg font-bold text-slate-100">
                  Connect Your Computer
                </ModalTitle>
                <ModalDescription className="text-xs text-slate-400">
                  Simple, zero-terminal security setup with automatic device verification.
                </ModalDescription>
              </div>
            </div>
            <span className="text-xs font-mono font-medium text-slate-400 px-2.5 py-1 rounded-full bg-slate-800 border border-slate-700">
              Step {screen} of 5
            </span>
          </div>

          {/* Stepper progress dots */}
          <div className="mt-4 grid grid-cols-5 gap-2">
            {[
              "Choose Device",
              "Download",
              "Security",
              "Connecting",
              "Protected",
            ].map((label, idx) => {
              const stepNum = idx + 1;
              const isCompleted = stepNum < screen;
              const isCurrent = stepNum === screen;
              return (
                <div key={label} className="flex flex-col gap-1.5">
                  <div
                    className={`h-1.5 rounded-full transition-colors ${
                      isCompleted
                        ? "bg-emerald-500"
                        : isCurrent
                        ? "bg-cyan-500 animate-pulse"
                        : "bg-slate-800"
                    }`}
                  />
                  <span
                    className={`text-[10px] truncate ${
                      isCurrent
                        ? "font-semibold text-cyan-400"
                        : isCompleted
                        ? "text-emerald-400"
                        : "text-slate-500"
                    }`}
                  >
                    {label}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* ── Wizard Screen Content ───────────────────────────────────── */}
        <div className="p-6">
          {/* ================================================================ */}
          {/* SCREEN 1: CHOOSE DEVICE                                          */}
          {/* ================================================================ */}
          {screen === 1 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-base font-semibold text-slate-100">
                  Select your operating system
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Choose the type of computer you want to protect. CyberGuard AI provides pre-configured installers for both platforms.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {/* Windows Option */}
                <button
                  type="button"
                  onClick={() => setOs("windows")}
                  className={`text-left p-4 rounded-xl border transition-all flex flex-col justify-between ${
                    os === "windows"
                      ? "border-cyan-500 bg-cyan-950/30 ring-1 ring-cyan-500/50"
                      : "border-slate-800 bg-slate-950/60 hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div className="p-2.5 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
                      <Monitor size={28} />
                    </div>
                    {os === "windows" && (
                      <CheckCircle2 size={18} className="text-cyan-400" />
                    )}
                  </div>
                  <div className="mt-4">
                    <h4 className="text-sm font-bold text-slate-100">Windows Computer</h4>
                    <p className="text-xs text-slate-400 mt-1">
                      Windows 10, Windows 11 & Windows Server
                    </p>
                    <div className="mt-3 pt-3 border-t border-slate-800/80 text-[11px] text-slate-500 space-y-1">
                      <div>• 64-bit architecture (x64 / ARM64)</div>
                      <div>• Automated double-click installer (.exe)</div>
                      <div>• Standard Windows UAC permission</div>
                    </div>
                  </div>
                </button>

                {/* Linux Option */}
                <button
                  type="button"
                  onClick={() => setOs("linux")}
                  className={`text-left p-4 rounded-xl border transition-all flex flex-col justify-between ${
                    os === "linux"
                      ? "border-cyan-500 bg-cyan-950/30 ring-1 ring-cyan-500/50"
                      : "border-slate-800 bg-slate-950/60 hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div className="p-2.5 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
                      <Server size={28} />
                    </div>
                    {os === "linux" && (
                      <CheckCircle2 size={18} className="text-cyan-400" />
                    )}
                  </div>
                  <div className="mt-4">
                    <h4 className="text-sm font-bold text-slate-100">Linux Computer</h4>
                    <p className="text-xs text-slate-400 mt-1">
                      Ubuntu, Debian, RHEL, CentOS & Fedora
                    </p>
                    <div className="mt-3 pt-3 border-t border-slate-800/80 text-[11px] text-slate-500 space-y-1">
                      <div>• systemd init system supported</div>
                      <div>• Self-contained configuration package</div>
                      <div>• Root or sudo elevation for service</div>
                    </div>
                  </div>
                </button>
              </div>

              <div>
                <Input
                  label="Device Friendly Name (Optional)"
                  placeholder={os === "windows" ? "e.g. Work Laptop or Office PC" : "e.g. Web Server or Database Host"}
                  value={deviceName}
                  onChange={(e) => setDeviceName(e.target.value)}
                  helperText="If omitted, CyberGuard AI automatically labels it using your computer hostname."
                />
              </div>

              <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex items-start gap-3">
                <Info size={16} className="text-cyan-400 mt-0.5 shrink-0" />
                <p className="text-xs text-slate-400 leading-relaxed">
                  <span className="font-semibold text-slate-300">No command prompt required:</span> You will download a dedicated setup app that configures security monitoring automatically in the background.
                </p>
              </div>
            </div>
          )}

          {/* ================================================================ */}
          {/* SCREEN 2: DOWNLOAD INSTALLER                                     */}
          {/* ================================================================ */}
          {screen === 2 && deviceData && (
            <div className="space-y-6">
              <div>
                <h3 className="text-base font-semibold text-slate-100">
                  Download the CyberGuard AI Installer
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Your secure connection token has been prepared. Download the genuine installer package below.
                </p>
              </div>

              {/* Installer Information Card */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                      {os === "windows" ? <Monitor size={24} /> : <Server size={24} />}
                    </div>
                    <div>
                      <div className="text-sm font-bold text-slate-200">
                        {os === "windows" ? "CyberGuardSetup.exe" : "install_linux.sh"}
                      </div>
                      <div className="text-xs text-slate-400">
                        {deviceData.publisher}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 text-xs text-slate-400 font-mono">
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                      v{deviceData.installer_version}
                    </span>
                    <span>
                      {(deviceData.file_size_bytes / 1024).toFixed(1)} KB
                    </span>
                  </div>
                </div>

                {/* SHA256 Integrity Verification */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400 flex items-center gap-1.5 font-medium">
                      <FileCheck size={14} className="text-emerald-400" /> Package Integrity (SHA-256)
                    </span>
                    <button
                      type="button"
                      onClick={handleCopyHash}
                      className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono text-[11px]"
                    >
                      {copiedHash ? <Check size={12} /> : <Copy size={12} />}
                      {copiedHash ? "Copied" : "Copy Hash"}
                    </button>
                  </div>
                  <div className="p-2 rounded bg-slate-900 border border-slate-800 font-mono text-[11px] text-slate-400 truncate">
                    {deviceData.sha256_checksum}
                  </div>
                </div>

                {/* Primary Download Button */}
                <Button
                  className="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold py-3 text-sm shadow-lg shadow-cyan-500/20 flex items-center justify-center gap-2"
                  onClick={handleDownloadInstaller}
                  isLoading={isDownloading}
                >
                  <Download size={18} />
                  Download CyberGuard for {os === "windows" ? "Windows" : "Linux"}
                </Button>
              </div>

              {/* 3 Simple Instructions */}
              <div className="space-y-3">
                <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                  Quick 3-Step Setup
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                  <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 space-y-1">
                    <span className="font-bold text-cyan-400">1. Click Download</span>
                    <p className="text-slate-400 text-[11px]">
                      Save {os === "windows" ? "CyberGuardSetup.exe" : "install_linux.sh"} to your computer.
                    </p>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 space-y-1">
                    <span className="font-bold text-cyan-400">2. Run the Installer</span>
                    <p className="text-slate-400 text-[11px]">
                      Double-click to open. When asked for permission, click <strong className="text-slate-200">Yes</strong>.
                    </p>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 space-y-1">
                    <span className="font-bold text-cyan-400">3. Automatic Connect</span>
                    <p className="text-slate-400 text-[11px]">
                      The app securely pairs with your account without manual configuration.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ================================================================ */}
          {/* SCREEN 3: AUTOMATIC SECURE ENROLLMENT                            */}
          {/* ================================================================ */}
          {screen === 3 && deviceData && (
            <div className="space-y-6">
              <div>
                <h3 className="text-base font-semibold text-slate-100">
                  Automatic Security Handshake
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  How CyberGuard AI protects your computer without exposing permanent keys or passwords.
                </p>
              </div>

              {/* Security Architecture Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                  <div className="flex items-center gap-2 text-cyan-400">
                    <Clock size={16} />
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                      Short-Lived Token
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    A single-use pairing token valid for 30 minutes. It expires automatically and cannot be reused or replayed by an attacker.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                  <div className="flex items-center gap-2 text-emerald-400">
                    <Lock size={16} />
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                      Hardware Credential Storage
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Long-term keys are stored encrypted via Windows DPAPI or Linux Keyring, protected by your operating system's security subsystem.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                  <div className="flex items-center gap-2 text-amber-400">
                    <ShieldCheck size={16} />
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                      Isolated Tenant Identity
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    The collector is bound strictly to your private workspace ({deviceData.source_key}). Cross-tenant telemetry access is rejected.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                  <div className="flex items-center gap-2 text-purple-400">
                    <Zap size={16} />
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                      Instant One-Click Revocation
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    You can disconnect and revoke this device at any time from your CyberGuard dashboard, immediately stopping all event uploads.
                  </p>
                </div>
              </div>

              {/* Single-use Token Reference (for fallback/clipboard) */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400 font-medium">
                    Pre-paired One-Time Enrollment Token:
                  </span>
                  <button
                    type="button"
                    onClick={handleCopyToken}
                    className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono text-[11px]"
                  >
                    {copiedToken ? <Check size={12} /> : <Copy size={12} />}
                    {copiedToken ? "Copied" : "Copy Token"}
                  </button>
                </div>
                <div className="p-2.5 rounded bg-slate-900 border border-slate-800 font-mono text-xs text-slate-300 select-all">
                  {deviceData.enrollment_token}
                </div>
                <p className="text-[11px] text-slate-500">
                  The setup application reads this automatically from your downloaded installer or companion package.
                </p>
              </div>
            </div>
          )}

          {/* ================================================================ */}
          {/* SCREEN 4: INSTALLATION & CONNECTION PROGRESS                     */}
          {/* ================================================================ */}
          {screen === 4 && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                    Waiting for computer connection...
                    <Spinner size="sm" />
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Run the downloaded setup program. CyberGuard AI will detect each phase in real time.
                  </p>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => refetchStatus()}
                  className="text-xs text-slate-400 hover:text-slate-200"
                >
                  <RefreshCw size={12} className="mr-1" /> Refresh
                </Button>
              </div>

              {/* 8-Stage Real Progress List */}
              <div className="space-y-2">
                {[
                  {
                    title: "1. Installer downloaded",
                    done: Boolean(statusData?.installer_downloaded),
                    time: statusData?.installer_downloaded_at,
                    desc: "Package downloaded to computer",
                  },
                  {
                    title: "2. Installation started",
                    done: Boolean(statusData?.installation_started),
                    time: statusData?.installation_started_at,
                    desc: "User opened setup application",
                  },
                  {
                    title: "3. Collector installed",
                    done: Boolean(statusData?.collector_installed),
                    time: statusData?.collector_installed_at,
                    desc: "Service binaries and config registered",
                  },
                  {
                    title: "4. Device authenticated",
                    done: Boolean(statusData?.device_authenticated),
                    time: statusData?.device_authenticated_at,
                    desc: "Single-use enrollment token verified",
                  },
                  {
                    title: "5. Device enrolled",
                    done: Boolean(statusData?.device_enrolled),
                    time: statusData?.device_enrolled_at,
                    desc: "Encrypted device credential provisioned",
                  },
                  {
                    title: "6. Collector service started",
                    done: Boolean(statusData?.service_started),
                    time: statusData?.service_started_at,
                    desc: "Background monitoring process active",
                  },
                  {
                    title: "7. First heartbeat received",
                    done: Boolean(statusData?.first_heartbeat_received),
                    time: statusData?.first_heartbeat_at,
                    desc: "Mutual keep-alive handshake established",
                  },
                  {
                    title: "8. First telemetry batch received",
                    done: Boolean(statusData?.first_telemetry_received),
                    time: statusData?.first_telemetry_at,
                    desc: "System security telemetry persisted in database",
                  },
                ].map((step, idx) => (
                  <div
                    key={step.title}
                    className={`p-3 rounded-lg border transition-all flex items-center justify-between ${
                      step.done
                        ? "bg-emerald-950/20 border-emerald-500/30 text-emerald-200"
                        : idx === 0 || (idx > 0 && statusData && Object.values(statusData)[idx - 1])
                        ? "bg-slate-950 border-slate-800 text-slate-300"
                        : "bg-slate-950/40 border-slate-900 text-slate-500"
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      {step.done ? (
                        <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />
                      ) : (
                        <div className="w-4 h-4 rounded-full border border-slate-700 shrink-0 flex items-center justify-center">
                          <div className="w-1.5 h-1.5 rounded-full bg-slate-600" />
                        </div>
                      )}
                      <div>
                        <div className="text-xs font-semibold">{step.title}</div>
                        <div className="text-[11px] text-slate-400">{step.desc}</div>
                      </div>
                    </div>
                    {step.time && (
                      <span className="text-[10px] font-mono text-slate-500">
                        {formatRelativeTime(step.time)}
                      </span>
                    )}
                  </div>
                ))}
              </div>

              {/* Error Explanation & Recovery Hint */}
              {statusData?.error_message && (() => {
                const friendly = formatFriendlyError(statusData.error_message);
                return (
                  <div className="p-4 rounded-xl bg-rose-950/30 border border-rose-500/40 text-rose-200 space-y-2">
                    <div className="flex items-center gap-2 font-bold text-xs text-rose-300">
                      <AlertCircle size={16} /> Connection Assistance
                    </div>
                    <p className="text-xs font-semibold text-rose-200">{friendly.title}</p>
                    <p className="text-xs text-slate-300 bg-rose-950/60 p-2.5 rounded-lg border border-rose-500/20">
                      💡 {statusData.recovery_hint || friendly.hint}
                    </p>
                  </div>
                );
              })()}
            </div>
          )}

          {/* ================================================================ */}
          {/* SCREEN 5: CONNECTED DEVICE                                       */}
          {/* ================================================================ */}
          {screen === 5 && statusData && (
            <div className="space-y-6">
              <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-500/40 text-emerald-200 flex items-center gap-3">
                <CheckCircle2 size={28} className="text-emerald-400 shrink-0" />
                <div>
                  <h3 className="text-sm font-bold text-emerald-300">
                    Device Successfully Protected
                  </h3>
                  <p className="text-xs text-emerald-400/80 mt-0.5">
                    Authenticated heartbeat verified. Real-time security telemetry is actively streaming.
                  </p>
                </div>
              </div>

              {/* Genuine Device Specifications Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-semibold">
                    Device Name
                  </span>
                  <span className="text-xs font-bold text-slate-200 mt-1 block truncate">
                    {statusData.device_name}
                  </span>
                  <span className="text-[10px] font-mono text-slate-500 truncate block mt-0.5">
                    {statusData.source_key}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-semibold">
                    Operating System
                  </span>
                  <span className="text-xs font-bold text-slate-200 mt-1 block capitalize">
                    {statusData.os_type}
                  </span>
                  <span className="text-[10px] text-slate-500 truncate block mt-0.5">
                    v{statusData.collector_version}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-semibold">
                    Status
                  </span>
                  <span className="text-xs font-bold text-emerald-400 mt-1 flex items-center gap-1">
                    <CheckCircle2 size={12} /> ONLINE
                  </span>
                  <span className="text-[10px] text-slate-500 truncate block mt-0.5">
                    {statusData.last_heartbeat ? formatRelativeTime(statusData.last_heartbeat) : "Just now"}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-semibold">
                    Events Ingested
                  </span>
                  <span className="text-xs font-bold text-cyan-400 mt-1 block">
                    {statusData.events_received} events
                  </span>
                  <span className="text-[10px] text-slate-500 truncate block mt-0.5">
                    {statusData.last_event_at ? formatRelativeTime(statusData.last_event_at) : "Active stream"}
                  </span>
                </div>
              </div>

              {/* Collection Permissions Card */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2.5">
                <div className="flex items-center gap-2 text-xs font-bold text-slate-300 uppercase tracking-wider">
                  <Activity size={14} className="text-cyan-400" /> Authorized Collection Scopes
                </div>
                <div className="space-y-1.5 text-xs text-slate-400">
                  {statusData.collection_permissions.map((perm) => (
                    <div key={perm} className="flex items-center gap-2">
                      <Check size={12} className="text-emerald-400 shrink-0" />
                      <span>{perm}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ── Collapsible Help & Troubleshooting Section ── */}
          <div className="mt-4 pt-3 border-t border-slate-800/80">
            <button
              type="button"
              onClick={() => setShowHelp(!showHelp)}
              className="flex items-center justify-between w-full text-xs font-medium text-slate-400 hover:text-cyan-400 transition-colors py-1"
            >
              <span className="flex items-center gap-1.5">
                <HelpCircle size={14} className="text-cyan-400" />
                Need Help Connecting Your Device?
              </span>
              <span className="text-[11px] text-slate-500 underline">
                {showHelp ? "Hide troubleshooting tips" : "Show troubleshooting guide"}
              </span>
            </button>

            {showHelp && (
              <div className="mt-3 p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 text-xs text-slate-300 space-y-3">
                <div>
                  <h5 className="font-semibold text-slate-200">
                    Windows asked for administrator permission?
                  </h5>
                  <p className="text-slate-400 text-[11px] mt-0.5">
                    Windows needs permission to install the security monitoring service. When prompted by Windows User Account Control (UAC), click <strong>Yes</strong> to allow the installation.
                  </p>
                </div>
                <div>
                  <h5 className="font-semibold text-slate-200">
                    Is your computer stuck on "Waiting for first heartbeat"?
                  </h5>
                  <p className="text-slate-400 text-[11px] mt-0.5">
                    Your computer is not currently communicating with CyberGuard AI. Check its internet connection and verify that the installer finished running.
                  </p>
                </div>
                <div>
                  <h5 className="font-semibold text-slate-200">
                    Did the connection token expire?
                  </h5>
                  <p className="text-slate-400 text-[11px] mt-0.5">
                    We couldn't securely connect this computer. Return to CyberGuard AI and generate a fresh connection to try again.
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* ── Wizard Footer Navigation ────────────────────────────────── */}
        <div className="bg-slate-950 border-t border-slate-800 px-6 py-4 flex items-center justify-between">
          {screen === 1 && (
            <>
              <Button variant="ghost" size="sm" onClick={handleClose}>
                Cancel
              </Button>
              <Button
                size="sm"
                className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold"
                onClick={() => registerMutation.mutate()}
                isLoading={registerMutation.isPending}
              >
                Continue to Download <ArrowRight size={14} className="ml-1" />
              </Button>
            </>
          )}

          {screen === 2 && (
            <>
              <Button variant="ghost" size="sm" onClick={() => setScreen(1)}>
                <ArrowLeft size={14} className="mr-1" /> Back
              </Button>
              <Button
                size="sm"
                className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold"
                onClick={() => setScreen(3)}
              >
                Next: Security Handshake <ArrowRight size={14} className="ml-1" />
              </Button>
            </>
          )}

          {screen === 3 && (
            <>
              <Button variant="ghost" size="sm" onClick={() => setScreen(2)}>
                <ArrowLeft size={14} className="mr-1" /> Back
              </Button>
              <Button
                size="sm"
                className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold"
                onClick={() => setScreen(4)}
              >
                Start Connection Monitor <ArrowRight size={14} className="ml-1" />
              </Button>
            </>
          )}

          {screen === 4 && (
            <>
              <Button variant="ghost" size="sm" onClick={() => setScreen(2)}>
                <ArrowLeft size={14} className="mr-1" /> Back to Download
              </Button>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleClose}
                  className="border-slate-800 text-slate-400 text-xs"
                >
                  Close & Wait in Background
                </Button>
              </div>
            </>
          )}

          {screen === 5 && (
            <>
              <Button
                variant="outline"
                size="sm"
                onClick={handleClose}
                className="border-slate-800 text-slate-300"
              >
                Close
              </Button>
              <Button
                size="sm"
                className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold"
                onClick={() => {
                  handleClose();
                  if (activeDeviceId) {
                    navigate(`/personal/devices/${activeDeviceId}`);
                  }
                }}
              >
                View Device Telemetry <ArrowRight size={14} className="ml-1" />
              </Button>
            </>
          )}
        </div>
      </ModalContent>
    </Modal>
  );
}
