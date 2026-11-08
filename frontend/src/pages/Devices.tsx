/**
 * CyberGuard AI — Devices (Sources) Page
 * ============================================================================
 * 
 * Manages the enrollment and health of data collectors.
 * 
 * Features:
 *   - Lists all connected devices (Windows, Linux, macOS).
 *   - Shows live connection status (Heartbeat check).
 *   - "Connect Device" modal:
 *       1. Choose OS.
 *       2. Backend creates a Source and generates an Enrollment Token.
 *       3. Displays the exact installation command for the user to copy.
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Monitor, Server, Apple, Copy, CheckCircle2, XCircle, AlertCircle } from "lucide-react";
import { toast } from "sonner";
import { formatRelativeTime } from "@/lib/utils";

import { api } from "@/lib/api";
import type { PaginatedResponse } from "@/types";
import { Card, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Spinner } from "@/components/ui/Spinner";
import { Modal, ModalContent, ModalHeader, ModalTitle, ModalDescription, ModalFooter } from "@/components/ui/Modal";
import {
  TableWrapper, Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from "@/components/ui/Table";


// ============================================================================
// LOCAL TYPES (Mirroring backend schema)
// ============================================================================

interface DeviceItem {
  id: string;
  name: string;
  type: string;
  os_version: string | null;
  agent_version: string | null;
  hostname: string | null;
  ip_address: string | null;
  status: string;
  last_scan: string | null;
  last_heartbeat: string | null;
  threat_count: number;
  collector_connected: boolean;
  source_key: string;
  created_at: string;
}

type OS = "windows" | "linux" | "macos";


// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function Devices() {
  const navigate = useNavigate();
  const [isModalOpen, setIsModalOpen] = useState(false);

  // ── Fetch Devices ─────────────────────────────────────────────────────
  const { data, isLoading } = useQuery<{ items: DeviceItem[]; total: number }>({
    queryKey: ["devices"],
    queryFn: async () => {
      const { data } = await api.get<{ items: DeviceItem[]; total: number }>("/devices");
      return data;
    },
    refetchInterval: 8000, 
  });

  return (
    <div className="space-y-6">
      
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Devices
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Connect your servers, laptops, and firewalls to start monitoring.
          </p>
        </div>
        <Button onClick={() => setIsModalOpen(true)} leftIcon={<Plus size={16} />}>
          Connect Device
        </Button>
      </div>

      {/* ── Device Table ───────────────────────────────────────────────── */}
      {isLoading ? (
        <Card><CardContent className="p-12"><Spinner size="lg" label="Loading devices..." /></CardContent></Card>
      ) : data?.items.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center p-12 text-center">
            <Monitor size={48} className="text-slate-300 dark:text-slate-600 mb-4" />
            <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">No devices connected</h3>
            <p className="mt-1 text-sm text-slate-500 max-w-sm">
              Install the CyberGuard collector on your machine to begin streaming logs and detecting threats.
            </p>
            <Button className="mt-6" onClick={() => setIsModalOpen(true)}>
              Connect your first device
            </Button>
          </CardContent>
        </Card>
      ) : (
        <TableWrapper>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Device Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="hidden md:table-cell">Last Seen</TableHead>
                <TableHead className="text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data?.items.map((device) => (
                <TableRow
                  key={device.id}
                  interactive
                  onClick={() => navigate(`/personal/devices/${device.id}`)}
                  className="cursor-pointer"
                >
                  <TableCell>
                    <div className="flex flex-col">
                      <span className="font-medium text-slate-900 dark:text-slate-100">
                        {device.name}
                      </span>
                      <span className="text-xs text-slate-500 font-mono">
                        {device.hostname || device.source_key}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2 text-sm capitalize text-slate-600 dark:text-slate-400">
                      {device.type === "windows" && <Monitor size={16} />}
                      {device.type === "linux" && <Server size={16} />}
                      {device.type === "macos" && <Apple size={16} />}
                      {device.type}
                    </div>
                  </TableCell>
                  <TableCell>
                    {device.collector_connected ? (
                      <div className="flex items-center gap-1.5 text-sm font-medium text-green-600 dark:text-green-400">
                        <CheckCircle2 size={16} /> Online
                      </div>
                    ) : device.status === "pending_enrollment" || device.status === "pending" ? (
                      <div className="flex items-center gap-1.5 text-sm font-medium text-amber-600 dark:text-amber-400">
                        <AlertCircle size={16} /> Waiting for install...
                      </div>
                    ) : (
                      <div className="flex items-center gap-1.5 text-sm font-medium text-slate-500 dark:text-slate-400">
                        <XCircle size={16} /> Offline
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="hidden md:table-cell text-sm text-slate-500">
                    {device.last_heartbeat ? formatRelativeTime(device.last_heartbeat) : "Never"}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate(`/personal/devices/${device.id}`);
                      }}
                    >
                      View Details
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableWrapper>
      )}

      <ConnectDeviceModal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} />
    </div>
  );
}


// ============================================================================
// CONNECT DEVICE MODAL (The Onboarding Flow)
// ============================================================================

interface DeviceCreated {
  id: string;
  source_key: string;
  name: string;
  os_type: string;
  status: string;
  enrollment_token: string;
  expires_at: string;
  powershell_install_command: string;
  bash_install_command: string;
}

function ConnectDeviceModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [os, setOs] = useState<OS>("windows");
  const [deviceName, setDeviceName] = useState("");
  const [createdDevice, setCreatedDevice] = useState<DeviceCreated | null>(null);

  // ── Mutation: Register Device + Get Token + Commands ─────────────────
  const createDeviceMutation = useMutation({
    mutationFn: async () => {
      const { data } = await api.post<DeviceCreated>("/devices", {
        name: deviceName || `My ${os.charAt(0).toUpperCase() + os.slice(1)} Device`,
        os_type: os,
      });
      return data;
    },
    onSuccess: (data) => {
      setCreatedDevice(data);
      queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
    onError: (err: any) => {
      toast.error(err.message || "Failed to generate enrollment token");
    },
  });

  // Reset state when modal closes
  const handleClose = () => {
    setTimeout(() => {
      setCreatedDevice(null);
      setDeviceName("");
      setOs("windows");
    }, 200);
    onClose();
  };

  const getCommand = () => {
    if (!createdDevice) return "";
    if (os === "windows") {
      return createdDevice.powershell_install_command;
    }
    return createdDevice.bash_install_command;
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(getCommand());
    toast.success("Command copied to clipboard");
  };

  return (
    <Modal open={isOpen} onOpenChange={handleClose}>
      <ModalContent className="max-w-2xl">
        
        {/* ── Step 1: Configure ─────────────────────────────────────────── */}
        {!createdDevice ? (
          <>
            <ModalHeader>
              <ModalTitle>Connect a Device</ModalTitle>
              <ModalDescription>
                Choose your operating system and we'll generate an installation command.
              </ModalDescription>
            </ModalHeader>

            <div className="py-6 space-y-6">
              <div className="space-y-2">
                <label className="text-sm font-medium text-slate-700 dark:text-slate-300">Operating System</label>
                <div className="grid grid-cols-3 gap-3">
                  <button
                    onClick={() => setOs("windows")}
                    className={`flex flex-col items-center justify-center gap-2 rounded-lg border p-4 transition-colors ${os === "windows" ? "border-brand-500 bg-brand-50 text-brand-700 dark:bg-brand-900/20 dark:text-brand-400" : "border-slate-200 hover:border-slate-300 dark:border-slate-700 dark:hover:border-slate-600"}`}
                  >
                    <Monitor size={24} />
                    <span className="text-sm font-medium">Windows</span>
                  </button>
                  <button
                    onClick={() => setOs("linux")}
                    className={`flex flex-col items-center justify-center gap-2 rounded-lg border p-4 transition-colors ${os === "linux" ? "border-brand-500 bg-brand-50 text-brand-700 dark:bg-brand-900/20 dark:text-brand-400" : "border-slate-200 hover:border-slate-300 dark:border-slate-700 dark:hover:border-slate-600"}`}
                  >
                    <Server size={24} />
                    <span className="text-sm font-medium">Linux</span>
                  </button>
                  <button
                    onClick={() => setOs("macos")}
                    className={`flex flex-col items-center justify-center gap-2 rounded-lg border p-4 transition-colors ${os === "macos" ? "border-brand-500 bg-brand-50 text-brand-700 dark:bg-brand-900/20 dark:text-brand-400" : "border-slate-200 hover:border-slate-300 dark:border-slate-700 dark:hover:border-slate-600"}`}
                  >
                    <Apple size={24} />
                    <span className="text-sm font-medium">macOS</span>
                  </button>
                </div>
              </div>

              <Input
                label="Device Name (Optional)"
                placeholder="e.g. Production Web Server"
                value={deviceName}
                onChange={(e) => setDeviceName(e.target.value)}
                helperText="If left blank, we'll use your hostname."
              />
            </div>

            <ModalFooter>
              <Button variant="ghost" onClick={handleClose}>Cancel</Button>
              <Button onClick={() => createDeviceMutation.mutate()} isLoading={createDeviceMutation.isPending}>
                Generate Command
              </Button>
            </ModalFooter>
          </>
        ) : (
          
          /* ── Step 2: Show Command ────────────────────────────────────── */
          <>
            <ModalHeader>
              <ModalTitle>Run the Installation Command</ModalTitle>
              <ModalDescription>
                Copy and run this command on your device. This token expires in 15 minutes.
              </ModalDescription>
            </ModalHeader>

            <div className="py-6 space-y-4">
              <div className="relative">
                <pre className="rounded-lg bg-slate-900 p-4 text-sm text-green-400 overflow-x-auto dark:bg-slate-950 font-mono">
                  {getCommand()}
                </pre>
                <Button
                  size="sm"
                  variant="secondary"
                  className="absolute right-2 top-2"
                  onClick={copyToClipboard}
                  leftIcon={<Copy size={14} />}
                >
                  Copy
                </Button>
              </div>

              <div className="rounded-lg bg-amber-50 p-3 text-sm text-amber-800 dark:bg-amber-900/30 dark:text-amber-300 flex items-start gap-2">
                <AlertCircle size={16} className="mt-0.5 shrink-0" />
                <p>The device status will automatically change to <strong>Online</strong> once the collector connects. You can close this window safely.</p>
              </div>
            </div>

            <ModalFooter>
              <Button onClick={handleClose}>Done</Button>
            </ModalFooter>
          </>
        )}

      </ModalContent>
    </Modal>
  );
}
