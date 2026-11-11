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

import { useState, useEffect } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Monitor, Server, Apple, Radio, CheckCircle2, XCircle, AlertCircle, Trash2 } from "lucide-react";
import { formatRelativeTime } from "@/lib/utils";
import { toast } from "sonner";

import { api } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Spinner } from "@/components/ui/Spinner";
import {
  TableWrapper, Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from "@/components/ui/Table";
import {
  Modal,
  ModalContent,
  ModalHeader,
  ModalTitle,
  ModalDescription,
  ModalFooter,
} from "@/components/ui/Modal";
import { DeviceConnectionWizard } from "@/components/devices/DeviceConnectionWizard";


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
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const [isModalOpen, setIsModalOpen] = useState(searchParams.get("connect") === "true");
  const [deviceToDelete, setDeviceToDelete] = useState<DeviceItem | null>(null);

  useEffect(() => {
    if (searchParams.get("connect") === "true") {
      setIsModalOpen(true);
    }
  }, [searchParams]);

  // ── Fetch Devices ─────────────────────────────────────────────────────
  const { data, isLoading } = useQuery<DeviceItem[] | { items: DeviceItem[]; total?: number }>({
    queryKey: ["devices"],
    queryFn: async () => {
      const { data } = await api.get<DeviceItem[] | { items: DeviceItem[]; total?: number }>("/devices");
      return data;
    },
    refetchInterval: 8000, 
  });

  // ── Remove Device Mutation ────────────────────────────────────────────
  const deleteDeviceMutation = useMutation({
    mutationFn: async (id: string) => {
      const { data } = await api.delete(`/devices/${id}`);
      return data;
    },
    onSuccess: () => {
      toast.success(
        deviceToDelete
          ? `Device "${deviceToDelete.name}" removed successfully.`
          : "Device removed successfully."
      );
      setDeviceToDelete(null);
      queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
    onError: (err: any) => {
      toast.error(err?.message || "Failed to remove device");
    },
  });

  const deviceList: DeviceItem[] = Array.isArray(data)
    ? data
    : (data?.items ?? []);

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
      ) : deviceList.length === 0 ? (
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
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {deviceList.map((device) => (
                <TableRow
                  key={device.id}
                  interactive
                  onClick={() => navigate(`/personal/devices/${device.id}`)}
                  className="cursor-pointer hover:bg-slate-800/40 transition-colors"
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
                      {device.type === "network" && <Radio size={16} className="text-cyan-400" />}
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
                    <div
                      className="flex items-center justify-end gap-1.5"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => navigate(`/personal/devices/${device.id}`)}
                        className="text-xs text-slate-300 hover:text-white"
                      >
                        View Details
                      </Button>

                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setDeviceToDelete(device)}
                        className="text-xs text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 p-2 transition-colors"
                        title="Remove Device"
                      >
                        <Trash2 size={15} />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableWrapper>
      )}

      {/* Remove Device Confirmation Modal */}
      <Modal open={!!deviceToDelete} onOpenChange={() => setDeviceToDelete(null)}>
        <ModalContent className="max-w-md bg-slate-900 border-slate-800 text-slate-100">
          <ModalHeader>
            <ModalTitle className="text-base font-bold flex items-center gap-2 text-rose-400">
              <Trash2 size={18} /> Remove Device
            </ModalTitle>
            <ModalDescription className="text-xs text-slate-400">
              Are you sure you want to remove <span className="font-semibold text-slate-200">"{deviceToDelete?.name}"</span>?
            </ModalDescription>
          </ModalHeader>
          <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2 text-xs text-slate-400">
            <p>
              This will permanently revoke all endpoint collector credentials and remove this machine from active monitoring.
            </p>
            <p className="text-[11px] text-slate-500 font-mono">
              Hostname: {deviceToDelete?.hostname || deviceToDelete?.source_key}
            </p>
          </div>
          <ModalFooter className="flex justify-end gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setDeviceToDelete(null)}
              disabled={deleteDeviceMutation.isPending}
            >
              Cancel
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                if (deviceToDelete) {
                  deleteDeviceMutation.mutate(deviceToDelete.id);
                }
              }}
              isLoading={deleteDeviceMutation.isPending}
              className="bg-rose-600 hover:bg-rose-500 text-white border-rose-600 font-semibold text-xs"
            >
              Confirm Remove
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      <DeviceConnectionWizard
        isOpen={isModalOpen}
        onClose={() => {
          setIsModalOpen(false);
          setSearchParams({});
        }}
      />
    </div>
  );
}
